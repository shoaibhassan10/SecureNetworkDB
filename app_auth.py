"""
==============================================================================
SecureNetworkDB: Enterprise Credential Vault & SIEM Attack Monitoring System
Entry Point: app_auth.py / app.py
==============================================================================
Description:
    Runs the Flask application connected to local SQL Server instance:
    Server=.\\SHOAIB;Database=SecureNetworkDB;Trusted_Connection=yes;
==============================================================================
"""

import sys
from app import app, auto_seed_and_repair_db

if __name__ == '__main__':
    print("=" * 82)
    print("  ENTERPRISE CREDENTIAL VAULT & SIEM ATTACK MONITORING SYSTEM")
    print("  Database Target: Server=.\\SHOAIB;Database=SecureNetworkDB")
    print("=" * 82)
    print("  * My Protected Credential Vault & SIEM Portal: http://127.0.0.1:5000/dashboard")
    print("  * SOC Admin Operations & Threat Center      : http://127.0.0.1:5000/admin")
    print("  * Multi-Role Authentication Gateway         : http://127.0.0.1:5000/login")
    print("=" * 82)
    
    # Run self-healing database check & upsert specified users
    try:
        auto_seed_and_repair_db()
        print("[SUCCESS] SQL Server connection, User_Vault table, and schema integrity validated.")
        print("-" * 82)
        print("  [RBAC IDENTITIES & VAULT CREDENTIALS SYNCED]:")
        print("  * 2412348  | balti_admin    | Tier 3 (Admin)             | Balti123   | Active")
        print("  * 2412372  | touqeer_ahmed  | Tier 2 (Security Operator) | Touqeer123 | Active")
        print("  * 2412342  | sidra_naz      | Tier 2 (Security Operator) | Sidra123   | Active")
        print("  * 2412349  | sarah_operator | Tier 2 (Security Operator) | Operator123| Active")
        print("  * 2412329  | aleeza_javed   | Tier 1 (SOC Analyst)       | Aleeza123  | Active")
        print("  * 24123493 | kazma_badar    | Tier 1 (SOC Analyst)       | Kazma123   | Pending_Audit")
        print("-" * 82)
    except Exception as e:
        print(f"[WARNING] Database check encountered: {e}")

    app.run(host='0.0.0.0', port=5000, debug=True)
