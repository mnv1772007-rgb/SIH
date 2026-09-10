"""
Hash Extractor — SHA256 fingerprinting of body text, HTML, and attachments.
SIH 26106 — IronPulse | Role 1
"""

from __future__ import annotations

import hashlib
from typing import Optional

from ..parser.body_extractor import BodyContent, Attachment
from ..schema.forensic_report import AttachmentInfo, IocBundle


class HashExtractor:
    def enrich_ioc_bundle(
        self,
        bundle: IocBundle,
        body: BodyContent,
    ) -> IocBundle:
        """
        Compute SHA256 of text body, HTML body, and all attachments.
        Populates:
          - bundle.body_text_sha256
          - bundle.body_html_sha256
          - bundle.attachments  (AttachmentInfo list)
        """
        if body.text_plain:
            bundle.body_text_sha256 = hashlib.sha256(
                body.text_plain.encode("utf-8", errors="replace")
            ).hexdigest()

        if body.text_html:
            bundle.body_html_sha256 = hashlib.sha256(
                body.text_html.encode("utf-8", errors="replace")
            ).hexdigest()

        for att in body.attachments:
            bundle.attachments.append(_to_attachment_info(att))

        return bundle


def _to_attachment_info(att: Attachment) -> AttachmentInfo:
    return AttachmentInfo(
        filename=att.filename,
        content_type=att.content_type,
        size_bytes=att.size_bytes,
        md5=att.md5,
        sha1=att.sha1,
        sha256=att.sha256,
        is_executable=att.is_executable,
        is_archive=att.is_archive,
        is_office_doc=att.is_office_doc,
    )
