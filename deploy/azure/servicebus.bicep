// Service Bus for the ticket topics, locked down:
//   * disableLocalAuth: SAS keys and connection strings do not work at all; only Entra ID
//   * minimumTlsVersion 1.2; publicNetworkAccess Disabled; reachable only via private endpoint
//   * least-privilege RBAC scoped to the topic (sender) and to one subscription (receiver)
//   * duplicate detection on the topic; bounded delivery attempts, then dead-letter
//   * subscriptions filter on the `queue` application property set by the publisher

param namespaceName string
param location string = resourceGroup().location
param vnetName string
param peSubnetName string
param gatewayPrincipalId string
param workerBillingPrincipalId string

var queues = ['billing', 'technical', 'account', 'shipping']
var dataSenderRole = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'    // Azure Service Bus Data Sender
var dataReceiverRole = '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'  // Azure Service Bus Data Receiver

resource sb 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: namespaceName
  location: location
  sku: { name: 'Premium', tier: 'Premium', capacity: 1 }       // Premium is required for private endpoints
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
  }
}

resource topic 'Microsoft.ServiceBus/namespaces/topics@2022-10-01-preview' = {
  parent: sb
  name: 'tickets.routed'
  properties: {
    requiresDuplicateDetection: true                // publisher sets message_id = ticket_id
    duplicateDetectionHistoryTimeWindow: 'PT10M'
    maxMessageSizeInKilobytes: 256                  // far above a TicketRouted message; caps abuse
    defaultMessageTimeToLive: 'P7D'
  }
}

resource subs 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2022-10-01-preview' = [for q in queues: {
  parent: topic
  name: q
  properties: {
    maxDeliveryCount: 5                             // a poison message is dead-lettered, not retried forever
    deadLetteringOnMessageExpiration: true
    deadLetteringOnFilterEvaluationExceptions: true
  }
}]

resource rules 'Microsoft.ServiceBus/namespaces/topics/subscriptions/rules@2022-10-01-preview' = [for (q, i) in queues: {
  parent: subs[i]
  name: 'only-${q}'
  properties: {
    filterType: 'SqlFilter'
    sqlFilter: { sqlExpression: 'queue = \'${q}\'' }
  }
}]

// The gateway may SEND to this one topic, and nothing else.
resource gatewaySend 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: topic
  name: guid(topic.id, gatewayPrincipalId, dataSenderRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', dataSenderRole)
    principalId: gatewayPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// The billing worker may RECEIVE from the billing subscription only.
resource workerReceive 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: subs[0]
  name: guid(subs[0].id, workerBillingPrincipalId, dataReceiverRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', dataReceiverRole)
    principalId: workerBillingPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Private endpoint + private DNS so the namespace name resolves to a VNet address.
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2023-09-01' existing = {
  name: '${vnetName}/${peSubnetName}'
}

resource pe 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: 'pe-${namespaceName}'
  location: location
  properties: {
    subnet: { id: subnet.id }
    privateLinkServiceConnections: [{
      name: 'sb'
      properties: { privateLinkServiceId: sb.id, groupIds: ['namespace'] }
    }]
  }
}

resource dns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.servicebus.windows.net'
  location: 'global'
}

resource dnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: dns
  name: 'link-${vnetName}'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: { id: resourceId('Microsoft.Network/virtualNetworks', vnetName) }
  }
}

resource dnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: pe
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{ name: 'sb', properties: { privateDnsZoneId: dns.id } }]
  }
}

output namespaceHost string = '${sb.name}.servicebus.windows.net'
