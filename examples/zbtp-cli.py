#!/usr/bin/env python3
import argparse
import json
import hashlib
import sys
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --- Constants & Error Codes ---
EXIT_SUCCESS = 0
EXIT_INVALID_FORMAT = 1
EXIT_INVALID_HASH = 2
EXIT_INVALID_SIG = 3
EXIT_ORPHAN = 4
EXIT_REVOKED = 6 # New exit code for revocation failure
EXIT_GENERIC_ERROR = 5

# --- Utils: Canonicalization & Hashing ---

def canonicalize(data):
    """
    Returns a bytes object of the JSON data with sorted keys and no whitespace.
    This ensures deterministic hashing/signing.
    """
    # Use standard library, which handles sorting of fields naturally in dumps.
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')

def hash_sha256(data_bytes):
    """Returns SHA-256 hex digest of bytes."""
    return hashlib.sha256(data_bytes).hexdigest()

def get_timestamp():
    """Returns current ISO 8601 UTC timestamp."""
    # Use Z for Zulu time, standard ISO 8601 practice
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def load_json(path):
    if not os.path.exists(path):
        print(f"Error: File not found: {path}")
        sys.exit(EXIT_GENERIC_ERROR)
    with open(path, 'r') as f:
        return json.load(f)

def save_json(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Created: {path}")

def load_private_key(path):
    """Loads a raw hex private key from a file."""
    if not os.path.exists(path):
        print(f"Error: Private key file not found: {path}")
        sys.exit(EXIT_GENERIC_ERROR)
    with open(path, 'r') as f:
        hex_key = f.read().strip()
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))

def pub_key_from_hex(hex_key):
    """Loads a public key object from a hex string."""
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))

def dt_from_iso(iso_str):
    """Parses an ISO 8601 string into a datetime object."""
    # Handle the 'Z' suffix properly
    if iso_str.endswith('Z'):
        iso_str = iso_str[:-1] + '+00:00'
    return datetime.fromisoformat(iso_str)

# --- Core Logic ---

def identity_generate(args):
    """Generates Ed25519 keypair. Saves public to JSON and private to .key file."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_key_hex = pub_bytes.hex()
    priv_key_hex = priv_bytes.hex()

    # 1. Save Public Identity JSON
    identity = {
        "public_key_hex": pub_key_hex,
        "key_version": 1,
        "created_at": get_timestamp()
    }
    
    # Handle rotation/revocation case where we need to name the file
    if args.rotate or args.revoke:
        print("Error: --rotate or --revoke must be used with an action specific subcommand.")
        sys.exit(EXIT_GENERIC_ERROR)
        
    save_json(identity, args.out)

    # 2. Save Private Key to separate file
    base_name = os.path.splitext(args.out)[0]
    key_filename = f"{base_name}.key"
    
    with open(key_filename, 'w') as f:
        f.write(priv_key_hex)
    
    if os.name == 'posix':
        os.chmod(key_filename, 0o600)
        
    print(f"Created Private Key: {key_filename} (DO NOT SHARE)")

def identity_rotate(args):
    """Handles key rotation: signs new key with old key."""
    
    if not args.signed_prev_key or not args.prev_identity:
        print("Error: --signed-prev-key and --prev-identity are required for rotation.")
        sys.exit(EXIT_GENERIC_ERROR)
        
    # Load old key pair
    old_ident = load_json(args.prev_identity)
    old_priv_key = load_private_key(args.signed_prev_key)
    old_pub_key_hex = old_ident['public_key_hex']
    old_version = old_ident.get('key_version', 1)
    
    # Generate new key pair
    new_priv_key_obj = ed25519.Ed25519PrivateKey.generate()
    new_pub_key_obj = new_priv_key_obj.public_key()
    
    new_priv_bytes = new_priv_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    new_pub_bytes = new_pub_key_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    new_pub_key_hex = new_pub_bytes.hex()
    new_priv_key_hex = new_priv_bytes.hex()

    # 1. Create Rotation Statement
    rotated_at = get_timestamp()
    rotation_statement = {
        "type": "zbtp.rotate",
        "previous_public_key": old_pub_key_hex,
        "new_public_key": new_pub_key_hex,
        "key_version": old_version + 1,
        "rotated_at": rotated_at
    }
    
    # Sign statement with the OLD private key
    canonical_bytes = canonicalize(rotation_statement)
    signature = old_priv_key.sign(canonical_bytes)
    rotation_statement["signature"] = signature.hex()
    
    # 2. Save New Private Key
    new_key_filename = f"private_key_v{old_version+1}.key"
    with open(new_key_filename, 'w') as f:
        f.write(new_priv_key_hex)
    if os.name == 'posix':
        os.chmod(new_key_filename, 0o600)
    print(f"Created New Private Key: {new_key_filename}")

    # 3. Save New Public Identity JSON (same format, updated version/key)
    new_identity = {
        "public_key_hex": new_pub_key_hex,
        "key_version": old_version + 1,
        "created_at": rotated_at
    }
    new_ident_filename = f"public_key_v{old_version+1}.json"
    save_json(new_identity, new_ident_filename)
    
    # 4. Save Rotation Proof
    rotation_proof_filename = f"rotate_v{old_version}_to_v{old_version+1}.json"
    save_json(rotation_statement, rotation_proof_filename)

def identity_revoke(args):
    """Handles key revocation: signs statement with the key being revoked."""
    
    if not args.signed_key or not args.identity:
        print("Error: --signed-key and --identity are required for revocation.")
        sys.exit(EXIT_GENERIC_ERROR)
        
    ident = load_json(args.identity)
    revoked_priv_key = load_private_key(args.signed_key)
    revoked_pub_key_hex = ident['public_key_hex']
    
    revoked_at = get_timestamp()
    
    # 1. Create Revocation Statement
    revocation_statement = {
        "type": "zbtp.revoke",
        "revoked_public_key": revoked_pub_key_hex,
        "revoked_at": revoked_at,
        "reason": args.reason or "No reason provided."
    }
    
    # Sign statement with the KEY BEING REVOKED
    canonical_bytes = canonicalize(revocation_statement)
    signature = revoked_priv_key.sign(canonical_bytes)
    revocation_statement["signature"] = signature.hex()
    
    # 2. Save Revocation Proof
    proof_filename = f"revoke_{revoked_pub_key_hex[:8]}_{revoked_at.split('T')[0]}.json"
    save_json(revocation_statement, proof_filename)


# --- Project and Contribution remain unchanged ---

def project_create(args):
    """Creates a canonical project definition."""
    
    participants = []
    if args.participants:
        for p_file in args.participants.split(','):
            p_data = load_json(p_file.strip())
            participants.append(p_data['public_key_hex'])
    
    participants.sort() 

    referenced_id = None
    if args.reference:
        try:
            ref_project = load_json(args.reference)
            referenced_id = ref_project.get('project_id')
            if not referenced_id:
                print(f"Error: Reference file '{args.reference}' does not contain a valid 'project_id'.")
                sys.exit(EXIT_GENERIC_ERROR)
        except Exception as e:
            print(f"Error loading reference project file: {e}")
            sys.exit(EXIT_GENERIC_ERROR)
            
    external_link = args.link if args.link else None

    desc_hash = hash_sha256(args.description.encode('utf-8'))
    salt = os.urandom(16).hex()

    project_payload = {
        "version": 1,
        "description_hash": desc_hash,
        "description_text": args.description,
        "participants": participants,
        "referenced_project_id": referenced_id,
        "external_link": external_link,
        "created_at": get_timestamp(),
        "random_salt": salt
    }

    canonical_bytes = canonicalize(project_payload)
    project_id = hash_sha256(canonical_bytes)
    
    project_payload["project_id"] = project_id
    save_json(project_payload, args.out)

def contribute(args):
    """Creates a signed contribution using external private key."""
    proj = load_json(args.project)
    ident = load_json(args.identity)
    
    if not args.signed:
        print("Error: --signed <private_key_file> is required to sign contribution.")
        sys.exit(EXIT_GENERIC_ERROR)
        
    priv_key = load_private_key(args.signed)
    
    # Sanity check key match
    derived_pub = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    
    if derived_pub != ident['public_key_hex']:
        print("Error: Private key provided does not match the public Identity JSON.")
        sys.exit(EXIT_INVALID_SIG)

    desc_hash = hash_sha256(args.description.encode('utf-8'))

    payload = {
        "type": "contribution",
        "project_id": proj['project_id'],
        "contributor_key": ident['public_key_hex'],
        "role": args.role,
        "description_hash": desc_hash,
        "description_text": args.description,
        "created_at": get_timestamp()
    }

    canonical_bytes = canonicalize(payload)
    signature = priv_key.sign(canonical_bytes)

    payload["signature"] = signature.hex()
    save_json(payload, args.out)

def confirm(args):
    """Signs a confirmation using external private key."""
    contrib = load_json(args.contribution)
    ident = load_json(args.identity)
    proj = load_json(args.project)

    if not args.signed:
        print("Error: --signed <private_key_file> is required to sign confirmation.")
        sys.exit(EXIT_GENERIC_ERROR)

    priv_key = load_private_key(args.signed)
    
    # Sanity check key match
    derived_pub = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    if derived_pub != ident['public_key_hex']:
        print("Error: Private key provided does not match the public Identity JSON.")
        sys.exit(EXIT_INVALID_SIG)

    contrib_copy = contrib.copy()
    if 'signature' in contrib_copy:
        del contrib_copy['signature']
    
    contribution_hash = hash_sha256(canonicalize(contrib_copy))

    payload = {
        "type": "confirmation",
        "project_id": proj['project_id'],
        "contribution_hash": contribution_hash,
        "confirmer_key": ident['public_key_hex'],
        "created_at": get_timestamp()
    }

    canonical_bytes = canonicalize(payload)
    signature = priv_key.sign(canonical_bytes)

    payload["signature"] = signature.hex()
    save_json(payload, args.out)

def export_proof(args):
    """Aggregates artifacts into a single proof.json."""
    proof = {
        "projects": [],
        "contributions": [],
        "confirmations": [],
        "identity_statements": [] # New field to hold rotation/revocation proofs
    }

    def load_list(arg_str):
        res = []
        if arg_str:
            for f in arg_str.split(','):
                res.append(load_json(f.strip()))
        return res
    
    for p in load_list(args.projects):
        proof['projects'].append(p)
    
    for c in load_list(args.contributions):
        proof['contributions'].append(c)

    for c in load_list(args.confirmations):
        proof['confirmations'].append(c)
        
    # Check for new identity statements
    if hasattr(args, 'identity_statements') and args.identity_statements:
        for s in load_list(args.identity_statements):
            proof['identity_statements'].append(s)

    save_json(proof, args.out)


def verify_proof(args):
    """Verifies the ZBTP proof graph, including key rotation and revocation."""
    proof = load_json(args.proof_file)
    
    required_keys = ["projects", "contributions", "confirmations"]
    for k in required_keys:
        if k not in proof:
            print(f"INVALID_PROOF_FORMAT: Missing key '{k}'")
            sys.exit(EXIT_INVALID_FORMAT)

    print("Verifying Proof...")
    
    # --- Identity Management (Rotation/Revocation) ---
    
    # Maps public key (hex) -> revocation timestamp (datetime)
    revoked_keys = {}
    # Maps public key (hex) -> is_rotated (bool)
    rotated_keys = {} 
    
    if proof.get('identity_statements'):
        print("\n--- Identity Statement Verification ---")
        for statement in proof['identity_statements']:
            statement_type = statement.get('type')
            
            if statement_type == "zbtp.rotate":
                # Rotation: Signed by previous key, links old key to new key.
                prev_key_hex = statement['previous_public_key']
                new_key_hex = statement['new_public_key']
                
                # Verify signature
                statement_calc = statement.copy()
                signature_hex = statement_calc.pop('signature', None)
                
                try:
                    prev_pub_key = pub_key_from_hex(prev_key_hex)
                    prev_pub_key.verify(bytes.fromhex(signature_hex), canonicalize(statement_calc))
                    
                    rotated_keys[prev_key_hex] = True
                    # If verification passes, the new key is the effective key for this identity path.
                    print(f"✔ rotation proof verified: {prev_key_hex[:8]}... → {new_key_hex[:8]}...")
                except Exception:
                    print(f"✖ rotation statement signature INVALID for key {prev_key_hex[:8]}...")
                    sys.exit(EXIT_INVALID_SIG)

            elif statement_type == "zbtp.revoke":
                # Revocation: Signed by the key being revoked.
                revoked_key_hex = statement['revoked_public_key']
                revoked_at_dt = dt_from_iso(statement['revoked_at'])
                
                # Verify signature
                statement_calc = statement.copy()
                signature_hex = statement_calc.pop('signature', None)
                
                try:
                    revoked_pub_key = pub_key_from_hex(revoked_key_hex)
                    revoked_pub_key.verify(bytes.fromhex(signature_hex), canonicalize(statement_calc))
                    
                    # Store the earliest known revocation time for this key
                    if revoked_key_hex not in revoked_keys or revoked_at_dt < revoked_keys[revoked_key_hex]:
                        revoked_keys[revoked_key_hex] = revoked_at_dt
                    
                    print(f"✔ revocation proof verified for key {revoked_key_hex[:8]}... (revoked at {statement['revoked_at']})")
                except Exception:
                    print(f"✖ revocation statement signature INVALID for key {revoked_key_hex[:8]}...")
                    sys.exit(EXIT_INVALID_SIG)
            
            else:
                print(f"⚠ Unknown identity statement type: {statement_type}")

    # 1. Verify Projects (No change in logic, only updated explanatory output)
    known_project_ids = set()
    for p in proof['projects']:
        p_calc = p.copy()
        stored_id = p_calc.pop('project_id', None)
        
        if 'referenced_project_id' not in p_calc: p_calc['referenced_project_id'] = None 
        if 'external_link' not in p_calc: p_calc['external_link'] = None 
        
        recalc_id = hash_sha256(canonicalize(p_calc))
        
        if recalc_id != stored_id:
            print(f"INVALID_PROJECT_HASH: Project {stored_id} hash mismatch.")
            sys.exit(EXIT_INVALID_HASH)
        
        known_project_ids.add(stored_id)
        if args.explain:
            ref_id = p.get('referenced_project_id')
            ref_info = f" (Ref: {ref_id[:8]}...)" if ref_id else ""
            link_info = f" (Link: {p.get('external_link')})" if p.get('external_link') else ""
            print(f"  [Project] {p.get('description_text', 'No Desc')} (ID: {stored_id[:8]}...){ref_info}{link_info} verified.")

    # 2. Verify Contributions
    print("\n--- Contribution Verification ---")
    known_contribution_hashes = {} 
    for i, c in enumerate(proof['contributions']):
        contributor_key = c['contributor_key']
        created_at_dt = dt_from_iso(c['created_at'])
        
        # A. Temporal Revocation Check (CRITICAL)
        if contributor_key in revoked_keys and created_at_dt >= revoked_keys[contributor_key]:
            print(f"✖ contribution #{i+1} by {contributor_key[:8]}... INVALIDATED by revocation at {revoked_keys[contributor_key].isoformat().replace('+00:00', 'Z')}")
            if args.strict:
                 sys.exit(EXIT_REVOKED)
            continue # Skip further checks on this contribution

        # B. Orphan Check
        if c['project_id'] not in known_project_ids:
            print(f"ORPHAN_CONTRIBUTION: Project {c['project_id']} not found.")
            sys.exit(EXIT_ORPHAN)

        # C. Signature Verify
        c_calc = c.copy()
        signature_hex = c_calc.pop('signature', None)
        
        if not signature_hex:
            print("INVALID_CONTRIBUTION_SIGNATURE: Missing signature")
            sys.exit(EXIT_INVALID_SIG)

        try:
            pub_key = pub_key_from_hex(contributor_key)
            pub_key.verify(bytes.fromhex(signature_hex), canonicalize(c_calc))
        except Exception:
            print(f"INVALID_CONTRIBUTION_SIGNATURE: Verification failed for contribution by {contributor_key[:8]}...")
            sys.exit(EXIT_INVALID_SIG)

        c_hash = hash_sha256(canonicalize(c_calc))
        known_contribution_hashes[c_hash] = c
        
        if args.explain:
            status = "✔" if contributor_key not in revoked_keys else "⚠ (Pre-revocation)"
            print(f"{status} Contribution #{i+1} by {contributor_key[:8]}... ({c['role']}) verified.")

    # 3. Verify Confirmations
    print("\n--- Confirmation Verification ---")
    confirmation_count = 0
    confirmations_map = {} 

    for i, cf in enumerate(proof['confirmations']):
        confirmer_key = cf['confirmer_key']
        created_at_dt = dt_from_iso(cf['created_at'])
        
        # A. Temporal Revocation Check (CRITICAL)
        if confirmer_key in revoked_keys and created_at_dt >= revoked_keys[confirmer_key]:
            print(f"✖ confirmation #{i+1} by {confirmer_key[:8]}... INVALIDATED by revocation at {revoked_keys[confirmer_key].isoformat().replace('+00:00', 'Z')}")
            if args.strict:
                 sys.exit(EXIT_REVOKED)
            continue # Skip further checks

        # B. Orphan Check
        if cf['contribution_hash'] not in known_contribution_hashes:
            print(f"ORPHAN_CONFIRMATION: Contribution {cf['contribution_hash']} not found.")
            sys.exit(EXIT_ORPHAN)

        # C. Signature Verify
        cf_calc = cf.copy()
        signature_hex = cf_calc.pop('signature', None)

        try:
            pub_key = pub_key_from_hex(confirmer_key)
            pub_key.verify(bytes.fromhex(signature_hex), canonicalize(cf_calc))
        except:
            print(f"INVALID_CONFIRMATION_SIGNATURE: Verification failed for confirmation by {confirmer_key[:8]}...")
            sys.exit(EXIT_INVALID_SIG)
        
        confirmation_count += 1
        
        if cf['contribution_hash'] not in confirmations_map:
            confirmations_map[cf['contribution_hash']] = []
        confirmations_map[cf['contribution_hash']].append(confirmer_key)
        
        if args.explain:
            status = "✔" if confirmer_key not in revoked_keys else "⚠ (Pre-revocation)"
            print(f"{status} Confirmation #{i+1} by {confirmer_key[:8]}... verified.")


    # 4. Final Report
    print("\n--- Summary ---")
    if args.json:
        result = {
            "valid": True,
            "counts": {
                "projects": len(proof['projects']),
                "contributions": len(known_contribution_hashes), # Only count valid/non-revoked ones
                "confirmations": confirmation_count
            },
            "revoked_keys": [k for k, v in revoked_keys.items()]
        }
        print(json.dumps(result, indent=2))
    elif args.explain:
        # Detailed explanation of valid contributions
        for c_hash, c_data in known_contribution_hashes.items():
            confirms = confirmations_map.get(c_hash, [])
            # Filter confirmations for validity if needed (already done above, but for output clarity)
            valid_confirms = [k for k in confirms if k not in revoked_keys or dt_from_iso(c_data['created_at']) < revoked_keys.get(k)]
            
            print(f"\nContribution: {c_data.get('description_text', 'Unknown')}")
            print(f"  Signer: {c_data['contributor_key'][:16]}...")
            print(f"  Confirmed by ({len(valid_confirms)} valid):")
            for k in valid_confirms:
                print(f"    - {k[:16]}...")

        # Report on revocation state
        if revoked_keys:
             print(f"\n⚠ WARNING: {len(revoked_keys)} keys found revoked in this proof.")
        else:
             print("✔ No revocation proofs provided.")

        print(f"\nProof verification SUCCESSFUL (Valid Contributions: {len(known_contribution_hashes)})")
    else:
        print(f"✔ Projects: {len(proof['projects'])} verified")
        print(f"✔ Contributions: {len(known_contribution_hashes)} valid")
        print(f"✔ Confirmations: {confirmation_count} valid")
        print(f"✔ Proof verification SUCCESSFUL")

    sys.exit(EXIT_SUCCESS)


# --- CLI Setup ---

def main():
    parser = argparse.ArgumentParser(description="zbtp-cli: Zero-Backend Trust Protocol Tool")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # 1. Identity
    p_ident = subparsers.add_parser('identity', help='Identity management')
    p_ident_actions = p_ident.add_subparsers(dest='action', required=True)

    # 1.1. Generate
    p_ident_actions.add_parser('generate', help='Generate new keypair').add_argument('--out', required=True, help='Output public identity file (e.g. user.json)')

    # 1.2. Rotate (NEW)
    p_rotate = p_ident_actions.add_parser('rotate', help='Rotate to a new key, signed by the previous key.')
    p_rotate.add_argument('--prev-identity', required=True, help='Previous public identity JSON file (to get public key and version).')
    p_rotate.add_argument('--signed-prev-key', required=True, help='Previous Private Key file (.key) for signing the rotation.')

    # 1.3. Revoke (NEW)
    p_revoke = p_ident_actions.add_parser('revoke', help='Revoke the current key, signed by the key being revoked.')
    p_revoke.add_argument('--identity', required=True, help='Public identity JSON file (of the key to be revoked).')
    p_revoke.add_argument('--signed-key', required=True, help='Private Key file (.key) of the key to be revoked (for signing).')
    p_revoke.add_argument('--reason', help='Optional reason for revocation.')

    # 2. Project
    p_proj = subparsers.add_parser('project', help='Project management')
    p_proj.add_argument('action', choices=['create'], help='Action to perform')
    p_proj.add_argument('--description', required=True, help='Project description')
    p_proj.add_argument('--participants', help='Comma-separated list of identity files')
    p_proj.add_argument('--reference', help='Optional: JSON file of an existing project to reference')
    p_proj.add_argument('--link', help='Optional: External URL link for the project (e.g., GitHub repo)') 
    p_proj.add_argument('--out', required=True, help='Output file for project')

    # 3. Contribute 
    p_cont = subparsers.add_parser('contribute', help='Add a contribution')
    p_cont.add_argument('--project', required=True, help='Project JSON file')
    p_cont.add_argument('--identity', required=True, help='Identity JSON file (Public Profile)')
    p_cont.add_argument('--signed', required=True, help='Private Key file (.key) for signing')
    p_cont.add_argument('--role', required=True, help='Role description')
    p_cont.add_argument('--description', required=True, help='Contribution description')
    p_cont.add_argument('--out', required=True, help='Output file for contribution')

    # 4. Confirm
    p_conf = subparsers.add_parser('confirm', help='Confirm a contribution')
    p_conf.add_argument('--project', required=True, help='Project JSON file')
    p_conf.add_argument('--contribution', required=True, help='Contribution JSON file')
    p_conf.add_argument('--identity', required=True, help='Identity JSON file (Public Profile)')
    p_conf.add_argument('--signed', required=True, help='Private Key file (.key) for signing')
    p_conf.add_argument('--out', required=True, help='Output file for confirmation')

    # 5. Export Proof (NEW ARG)
    p_exp = subparsers.add_parser('export-proof', help='Merge artifacts into a proof')
    p_exp.add_argument('--projects', help='Comma-separated project files')
    p_exp.add_argument('--contributions', help='Comma-separated contribution files')
    p_exp.add_argument('--confirmations', help='Comma-separated confirmation files')
    p_exp.add_argument('--identity-statements', help='Comma-separated rotation/revocation statement files (NEW)')
    p_exp.add_argument('--out', required=True, help='Output file for proof')

    # 6. Verify
    p_ver = subparsers.add_parser('verify', help='Verify a proof file')
    p_ver.add_argument('proof_file', help='The proof.json file')
    p_ver.add_argument('--strict', action='store_true', help='Fail on warnings (e.g., revoked contributions)')
    p_ver.add_argument('--json', action='store_true', help='Output JSON result')
    p_ver.add_argument('--explain', action='store_true', help='Explain graph details')

    args = parser.parse_args()

    if args.command == 'identity':
        if args.action == 'generate':
            identity_generate(args)
        elif args.action == 'rotate':
            identity_rotate(args)
        elif args.action == 'revoke':
            identity_revoke(args)
    elif args.command == 'project' and args.action == 'create':
        project_create(args)
    elif args.command == 'contribute':
        contribute(args)
    elif args.command == 'confirm':
        confirm(args)
    elif args.command == 'export-proof':
        export_proof(args)
    elif args.command == 'verify':
        verify_proof(args)

if __name__ == "__main__":
    main()
