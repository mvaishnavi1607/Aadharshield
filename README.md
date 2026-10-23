# AadharShield

Masks the first 8 digits of Aadhaar numbers (plus QR codes and 16-digit VIDs) in images, scan PDFs and Excel/CSV; keeps encrypted originals in a vault; provides a restricted, audited unmask tool. Runs fully on-premises (local OCR).

Docs (BRD, FSD, HLD, effort estimate): `D:\Finverge\Docs\Products\SecureAadhar\`. Synthetic data only is committed/generated; real samples live under that folder's `Samples\`.

## Run
```
pip install -r requirements.txt
python -m aadharshield.cli init-db --dev-users     # creates DB 'aadharshield' on local Postgres + test users (.dev-credentials.txt)
python -m aadharshield.cli serve                    # API + console on http://localhost:8790
python -m aadharshield.cli backfill D:\store --inplace [--manifest m.csv]
python -m aadharshield.cli watch D:\dropfolder      # ongoing masking, in place
python -m aadharshield.cli mask in.pdf out.pdf      # one-off, no DB/vault
python -m pytest tests -q                            # 17 tests (needs init-db --dev-users)
python tools/gen_synthetic.py data/synthetic         # fictitious Verhoeff-valid test set
```
Production: set `AADHARSHIELD_VAULT_KEY` and `AADHARSHIELD_JWT_KEY` (base64, 32 bytes) from your secret store/KMS; set DB URLs via `AADHARSHIELD_DB_URL`.

## Layout
`aadharshield/` imgmask (pixel masking) · masking (files) · detect (text) · vault · db · service (pipeline, back-fill, unmask) · api · cli · static/index.html (console) — `tests/` — `tools/gen_synthetic.py` — `docs/build_docs.py`
