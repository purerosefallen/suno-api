from typing import Any, Optional

from pydantic import BaseModel, Extra, Field


class Response(BaseModel):
    code: Optional[int] = 0
    msg: Optional[str] = "success"
    data: Optional[Any] = None


class CustomModeGenerateParam(BaseModel):
    """Generate with Custom Mode"""

    prompt: str = Field(..., description="lyrics")
    mv: str = Field(
        default="chirp-v4",
        description="model version, default: chirp-v4",
        examples=["chirp-v4"],
    )
    title: str = Field(..., description="song title")
    tags: str = Field(..., description="style of music")
    continue_at: Optional[float] = Field(
        default=None,
        description="continue a new clip from a previous song, format number",
        examples=[120],
    )
    continue_clip_id: Optional[str] = None
    class Config:
        extra = Extra.allow  # 允许额外字段


class DescriptionModeGenerateParam(BaseModel):
    """Generate with Song Description"""

    gpt_description_prompt: str
    make_instrumental: bool = False
    mv: str = Field(
        default="chirp-v4",
        description="model version, default: chirp-v4",
        examples=["chirp-v4"],
    )

    prompt: str = Field(
        default="",
        description="Placeholder, keep it as an empty string, do not modify it",
    )
    class Config:
        extra = Extra.allow  # 允许额外字段


class ConcatParam(BaseModel):
    """Concatenate multiple songs"""

    clip_id: str
    is_infill: bool = False


class GenerateLyricsParam(BaseModel):
    prompt: str = Field(..., description="lyrics")
