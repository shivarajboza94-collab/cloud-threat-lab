from flask import Flask, request, jsonify
import uuid, os

app = Flask(__name__)

# Mock database
INVOICES = {
    "inv-101": {"tenant_id": "tenant-a", "amount": 1200, "file": "inv-101.pdf"},
    "inv-102": {"tenant_id": "tenant-b", "amount": 4500, "file": "inv-102.pdf"}
}

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

# VULNERABLE ENDPOINT: Demonstrates BOLA / IDOR
@app.route("/api/v1/invoices/<invoice_id>", methods=["GET"])
def get_invoice_insecure(invoice_id):
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404
    return jsonify({"invoice": invoice}), 200

# SECURE ENDPOINT: Enforces Tenant Scoping
@app.route("/api/v2/invoices/<invoice_id>", methods=["GET"])
def get_invoice_secure(invoice_id):
    current_tenant = request.headers.get("X-Tenant-ID")
    invoice = INVOICES.get(invoice_id)
    
    if not invoice:
        return jsonify({"error": "Invoice not found"}), 404
    if invoice["tenant_id"] != current_tenant:
        return jsonify({"error": "Forbidden: Tenant isolation mismatch"}), 403
        
    return jsonify({"invoice": invoice}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
