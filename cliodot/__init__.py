from .client import _segment
"""Cliodot Python SDK: runtime Apps and Surface capabilities."""
from .client import AppClient, CliodotError
from .apps import AuthAppClient, OAuthAppClient, IdentityAppClient, MemoryAppClient, CommercialAppClient, Events, ProviderServicesClient, Surface
from .webhooks import sign_webhook_payload, verify_webhook_signature, verify_timestamped_signature
__all__=["AppClient","CliodotError","AuthAppClient","OAuthAppClient","IdentityAppClient","MemoryAppClient","CommercialAppClient","Events","ProviderServicesClient","Surface","sign_webhook_payload","verify_webhook_signature","verify_timestamped_signature"]
__version__="0.1.0"


# Extend the exported Commercial client with the remaining public methods.
_CommercialAppClientBase = CommercialAppClient
class CommercialAppClient(_CommercialAppClientBase):
    def list_customers(self, **params): return self.request("GET", "/v1/customers", params=params)
    def get_customer(self, customer_id): return self.request("GET", f"/v1/customers/{_segment(customer_id)}")
    def create_customer(self, **payload): return self.request("POST", "/v1/customers", data=payload)
    def list_features(self, **params): return self.request("GET", "/v1/features", params=params)
    def list_plans(self, **params): return self.request("GET", "/v1/plans", params=params)
    def list_subscriptions(self, **params): return self.request("GET", "/v1/subscriptions", params=params)
    def create_subscription(self, **payload): return self.request("POST", "/v1/subscriptions", data=payload)
    def subscribe(self, **payload): return self.create_subscription(**payload)
    def list_invoices(self, **params): return self.request("GET", "/v1/invoices", params=params)
    def get_invoice(self, invoice_id): return self.request("GET", f"/v1/invoices/{_segment(invoice_id)}")
    def get_feature(self, feature_id): return self.request("GET", f"/v1/features/{_segment(feature_id)}")
    def get_plan(self, plan_id): return self.request("GET", f"/v1/plans/{_segment(plan_id)}")
    def get_subscription(self, subscription_id): return self.request("GET", f"/v1/subscriptions/{_segment(subscription_id)}")
    def update_pending_subscription(self, subscription_id, **payload): return self.request("PATCH", f"/v1/subscriptions/{_segment(subscription_id)}", data=payload)
    def change_plan(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/change-plan", data=payload)
    def entitlement_topup(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/entitlement-topup", data=payload)
    def charge_usage(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/charge-usage", data=payload)
    def renew_subscription(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/renew", data=payload)
    def renew(self, subscription_id, **payload): return self.renew_subscription(subscription_id, **payload)
    def update_subscription_status(self, subscription_id, status): return self.request("PATCH", f"/v1/subscriptions/{_segment(subscription_id)}/status", data={"status": status})
    def archive_subscription(self, subscription_id): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/archive")
    def list_events(self, customer_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/events", params=params)
    def list_usage_events(self, customer_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/usage-events", params=params)
    def list_payment_methods(self): return self.request("GET", "/v1/payment-methods")
    def initiate_payment(self, **payload): return self.request("POST", "/v1/payments/initiate", data=payload)
    def confirm_payment(self, **payload): return self.request("POST", "/v1/payments/confirm", data=payload)
    def quote(self, **payload): return self.request("POST", "/v1/pricing/quote", data=payload)
    def preview_discount(self, **payload): return self.request("POST", "/v1/discounts/preview", data=payload)
    def list_discounts(self, **params): return self.request("GET", "/v1/discounts", params=params)
    def list_tax_rates(self, **params): return self.request("GET", "/v1/tax-rates", params=params)
    def list_addons(self, **params): return self.request("GET", "/v1/addons", params=params)
    def assign_seat(self, **payload): return self.request("POST", "/v1/seats/assign", data=payload)
    def unassign_seat(self, **payload): return self.request("POST", "/v1/seats/unassign", data=payload)
    def issue_license(self, **payload): return self.request("POST", "/v1/licenses/issue", data=payload)
    def validate_license(self, **payload): return self.request("POST", "/v1/licenses/validate", data=payload)
    def analytics(self, **params): return self.request("GET", "/v1/analytics", params=params)
