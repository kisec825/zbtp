`pip install cryptography`

Basic Workflow
  1. **Generate Identities** Generate user keys.
    `python3 zbtp-cli.py identity generate --out userA.json`
    `python3 zbtp-cli.py identity generate --out userB.json`
  2. **Create Project** Initializes a project.
    `python3 zbtp-cli.py project create --description "ZBTP Project" --participants userA.json,userB.json --link "https://github.com/kisec825/zbtp" --out ZBTPproject.json`
  3. **Contribute** Adds code.
    `python3 zbtp-cli.py contribute --project ZBTPproject.json --identity userA.json --signed userA.key --role "Lead Dev" --description "Initial Commit" --out contrib_by_userA.json`
  4. **Confirm** User A verifies my work and signs a confirmation.
    `python3 zbtp-cli.py confirm --project ZBTPproject.json --contribution contrib_by_userA.json --identity userB.json --signed userB.key --out confirm_by_userB.json`
  5. **Export Proof** Aggregate everything into a portable file.
    `python3 zbtp-cli.py export-proof --projects ZBTPproject.json --contributions contrib_by_userA.json --confirmations confirm_by_userB.json --out ZBTPproofv1.json`
  6. **Verify** Verify the proof completely offline.
    `python3 zbtp-cli.py verify ZBTPproofv1.json --explain`
  7. **Multiple** confirmations
    `python3 zbtp-cli.py identity generate --out reviewerA.json`
    `python3 zbtp-cli.py confirm --project ZBTPproject.json --contribution contrib_by_userA.json --identity reviewerA.json --signed reviewerA.key --out confirm_by_reviewerA.json`
    `python3 zbtp-cli.py export-proof --projects ZBTPproject.json --contributions contrib_by_userA.json --confirmations confirm_by_userB.json,confirm_by_reviewerA.json --out ZBTPproofv2.json`
    `python3 zbtp-cli.py verify ZBTPproofv2.json --explain`
  8. **Rotate** Key rotate
    `python3 zbtp-cli.py identity rotate --prev-identity userB.json --signed-prev-key userB.key`
  9. **Revoke** Key revoke
    `python3 zbtp-cli.py identity revoke --identity userA.json --signed-key userA.key --reason "Key compromised during travel."`
  > mv rotate_v1_to_v2.json userBv1_v2.json
  > mv private_key_v2.key userBv2.key
  > mv revoke_828c0b23_2025-12-16.json userAv2.json
  10. **Export Proof**
    `python3 zbtp-cli.py export-proof --projects ZBTPproject.json --contributions contrib_by_userA.json --confirmations confirm_by_userB.json,confirm_by_reviewerA.json --identity-statements userBv1_v2.json,userAv2.json --out proof_with_history.json`
  11. **Verify** Verify the final proof.
    `python3 zbtp-cli.py verify proof_with_history.json --explain`