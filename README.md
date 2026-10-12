# Blockchain-Based Secure FIR Filing System

Academic prototype: Django police portal, MongoDB records, NLP suggestions (TF-IDF + cosine similarity), Brotli compression, AES-256-CBC encryption, SHA-256 integrity checks, IPFS storage, and optional Ethereum/Geth smart contract integration.

## Run on Windows
1. Install Python 3.11/3.12 and MongoDB Community Server; start MongoDB.
2. Extract ZIP and open its folder in VS Code.
3. PowerShell:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Copy-Item .env.example .env
   python manage.py migrate
   python manage.py createsuperuser
   python manage.py runserver
   ```
4. Open `http://127.0.0.1:8000/login/`, sign in with the superuser.
5. Register a test FIR and run integrity verification.

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then activate again.

## Storage configuration
Default local fallback lets you test without IPFS. Start IPFS Kubo and set `IPFS_API_URL=http://127.0.0.1:5001` to use IPFS. Dashboard shows whether each record used IPFS or local storage.

For Ethereum integration, deploy `contracts/FIRRegistry.sol` to a private Geth chain, save its ABI as `contracts/FIRRegistry.abi.json`, and set the RPC URL, chain ID, contract address, and development private key in `.env`. Do not commit `.env` or real private keys.

## Prototype limitations
- The NLP corpus contains generic example descriptions, not verified BNS section mappings. Replace it with an authoritative, legally reviewed corpus before claiming section-level legal recommendations.
- GPS capture is not yet implemented; incident location is a human-readable form field.
- This is not production-ready. Use synthetic data only; production needs audited authentication/roles, secure key management, authenticated encryption, audit logs, backups, access controls, and legal/security approval.
- AES-CBC alone does not authenticate ciphertext; SHA-256 is checked before decryption. A production implementation should use an authenticated encryption mode such as AES-GCM.
