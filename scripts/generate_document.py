from app.database import Base, SessionLocal, engine
from app.models import Honeytoken
from app.honeytokens.documents import create_excel_honeytoken
import secrets


Base.metadata.create_all(bind=engine)


def generate_token():
    return f"HNY-{secrets.token_hex(4).upper()}"


db = SessionLocal()

try:
    token_id = generate_token()

    token = Honeytoken(
        token_id=token_id,
        document_name="Staff_Salary_Records.xlsx",
        document_type="xlsx",
        classification="CONFIDENTIAL",
        severity="HIGH"
    )

    db.add(token)
    db.commit()

    filepath = create_excel_honeytoken(
        token_id=token_id,
        filename="Staff_Salary_Records.xlsx"
    )

    print()
    print("======================================")
    print(" HONEYTOKEN DOCUMENT CREATED")
    print("======================================")
    print(f"Token ID : {token_id}")
    print(f"Document : {filepath}")
    print("Status   : ACTIVE")
    print("======================================")

finally:
    db.close()