from pydantic import BaseModel, ConfigDict, Field


class HoneytokenCreate(BaseModel):
    document_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    document_type: str = Field(
        ...,
        min_length=1,
        max_length=50,
    )

    classification: str = Field(
        default="CONFIDENTIAL",
        min_length=1,
        max_length=50,
    )

    severity: str = Field(
        default="HIGH",
        min_length=1,
        max_length=20,
    )


class HoneytokenResponse(BaseModel):
    token_id: str
    document_name: str
    document_type: str
    classification: str
    severity: str
    status: str

    model_config = ConfigDict(
        from_attributes=True
    )


class SecurityEventCreate(BaseModel):
    token_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    event_type: str = Field(
        default="TOKEN_TRIGGERED",
        min_length=1,
        max_length=100,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=100,
    )

    user_agent: str | None = Field(
        default=None,
        max_length=500,
    )