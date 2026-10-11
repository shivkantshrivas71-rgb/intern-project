"""
core/helpers.py — Shared Utility Helpers

Contains the custom CoreSchema annotation helper for serializing MongoDB
ObjectId values with Pydantic v2. Import this in every module's schema file.
"""
from typing import Any, Annotated
from bson import ObjectId
from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


# ─────────────────────────────────────────────────────────────────────────────
# PyObjectId — MongoDB ObjectId ↔ Pydantic v2 Bridge
# ─────────────────────────────────────────────────────────────────────────────

class PyObjectId(str):
    """
    Custom Pydantic v2 type that converts MongoDB ObjectId to a plain string.

    Problem: MongoDB stores document IDs as bson.ObjectId, which is not
             JSON-serializable — FastAPI raises a serialization error in responses.

    Solution: This class validates an ObjectId value and converts it to a string,
              allowing seamless JSON serialization in all API responses.
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """
        Define a custom CoreSchema for Pydantic v2.
        This method tells Pydantic how to validate and serialize this type.
        """
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def _validate(cls, value: Any) -> str:
        """
        Validate the value as an ObjectId and return it as a string.
        - If the value is an ObjectId instance  → convert to str
        - If the value is a valid ObjectId string → return as-is
        - Otherwise → raise ValueError
        """
        if isinstance(value, ObjectId):
            return str(value)
        if isinstance(value, str) and ObjectId.is_valid(value):
            return value
        raise ValueError(f"Invalid ObjectId: {value!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Annotated type alias — use directly in schema field definitions
# ─────────────────────────────────────────────────────────────────────────────

# Usage in schemas: id: ObjId = Field(None, alias="_id")
ObjId = Annotated[str, PyObjectId]


# ─────────────────────────────────────────────────────────────────────────────
# Helper: MongoDB document → clean response dict
# ─────────────────────────────────────────────────────────────────────────────

def serialize_doc(doc: dict) -> dict:
    """
    Convert a MongoDB document's `_id` ObjectId field to a plain string `id`
    and remove the `_id` key for a clean JSON response.
    """
    if doc is None:
        return {}
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    return doc


def serialize_list(docs: list[dict]) -> list[dict]:
    """Serialize a list of MongoDB documents using serialize_doc."""
    return [serialize_doc(doc) for doc in docs]
