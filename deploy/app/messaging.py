"""Secure Service Bus topic messaging — publisher and subscriber.

    pip install azure-identity azure-servicebus

Practices shown:
  * No connection strings or SAS keys. The pod authenticates with its workload identity
    (DefaultAzureCredential), and the namespace has local (SAS) auth disabled, so a
    leaked connection string is worthless. See azure/servicebus.bicep.
  * Least privilege per component: the router's identity holds only "Azure Service Bus
    Data Sender" on the tickets.routed topic; each worker holds only "Data Receiver" on
    its own subscription.
  * Every message is validated against the Module 05 message schema on BOTH sides:
    before sending (never publish something off-contract) and on receipt (never trust
    what arrives, even from your own topic). Invalid messages are dead-lettered with a
    reason instead of crashing the consumer or being silently dropped.
  * Correlation IDs are carried so a request can be traced across components.
  * Idempotent handling: redelivery is normal on a topic, so the handler dedupes on
    message_id.
"""

import json
import os
import sys

from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient, ServiceBusMessage

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema"))
from schema_check import validate  # noqa: E402  (copied from the Module 05 repo)

NAMESPACE = os.environ["SERVICEBUS_NAMESPACE"]          # e.g. sb-ticketbot.servicebus.windows.net
TOPIC = "tickets.routed"
MAX_BODY_BYTES = 16 * 1024

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema", "ticket-routed.v1.schema.json")) as f:
    SCHEMA = json.load(f)


def client():
    return ServiceBusClient(fully_qualified_namespace=NAMESPACE, credential=DefaultAzureCredential())


def publish(message, correlation_id):
    errors = validate(message, SCHEMA)
    if errors:
        raise ValueError(f"refusing to publish off-contract message: {errors}")
    with client() as sb, sb.get_topic_sender(topic_name=TOPIC) as sender:
        sender.send_messages(ServiceBusMessage(
            json.dumps(message),
            content_type="application/json",
            message_id=message["ticket_id"],               # lets Service Bus duplicate detection work
            correlation_id=correlation_id,
            application_properties={"queue": message["queue"]},   # subscription filters match on this
        ))


def consume(subscription, handle, max_messages=10):
    seen = set()                                          # in production: a durable store
    with client() as sb, sb.get_subscription_receiver(topic_name=TOPIC, subscription_name=subscription) as rx:
        for msg in rx.receive_messages(max_message_count=max_messages, max_wait_time=5):
            body = b"".join(msg.body)
            if len(body) > MAX_BODY_BYTES:
                rx.dead_letter_message(msg, reason="too_large", error_description=f"{len(body)} bytes")
                continue
            try:
                payload = json.loads(body)
            except ValueError:
                rx.dead_letter_message(msg, reason="not_json", error_description="body is not JSON")
                continue
            errors = validate(payload, SCHEMA)
            if errors:
                rx.dead_letter_message(msg, reason="schema_violation", error_description="; ".join(errors)[:1000])
                continue
            if msg.message_id in seen:
                rx.complete_message(msg)                  # duplicate delivery: already handled
                continue
            handle(payload, correlation_id=msg.correlation_id)
            seen.add(msg.message_id)
            rx.complete_message(msg)
