import plistlib
import os
import re
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

import pandas as pd


ROOT_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from scripts.artifact_report import ArtifactHtmlReport
from scripts.html_security import TrustedHtml, trust_html
import scripts.chat_rendering as chat_rendering
import scripts.ilapfuncs as ilapfuncs
import scripts.report as report
from scripts.artifacts import (
    biomeNotes,
    calendarAll,
    iconsScreen,
    kikPendingUploads,
    notificationsXI,
    protonMail,
    voiceRecordings,
    voiceTriggers,
    webClips,
)


class TestReportXssSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ileapp_xss_test_")
        self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)

        self.original_identifiers = ilapfuncs.identifiers
        self.original_lava_only_artifacts = ilapfuncs.lava_only_artifacts
        self.original_screen_output_path = getattr(
            ilapfuncs.OutputParameters, "screen_output_file_path", ""
        )
        self.original_devinfo_path = getattr(
            ilapfuncs.OutputParameters, "screen_output_file_path_devinfo", ""
        )
        self.original_lava_log_path = getattr(
            ilapfuncs.OutputParameters, "screen_output_file_path_lava_only", ""
        )

        ilapfuncs.OutputParameters.screen_output_file_path = self.original_screen_output_path
        ilapfuncs.OutputParameters.screen_output_file_path_devinfo = self.original_devinfo_path
        ilapfuncs.OutputParameters.screen_output_file_path_lava_only = self.original_lava_log_path

        ilapfuncs.identifiers = {}
        ilapfuncs.lava_only_artifacts = {}

    def tearDown(self):
        ilapfuncs.identifiers = self.original_identifiers
        ilapfuncs.lava_only_artifacts = self.original_lava_only_artifacts
        ilapfuncs.OutputParameters.screen_output_file_path = self.original_screen_output_path
        ilapfuncs.OutputParameters.screen_output_file_path_devinfo = self.original_devinfo_path
        ilapfuncs.OutputParameters.screen_output_file_path_lava_only = self.original_lava_log_path

    def _read_file(self, path):
        with open(path, "r", encoding="utf8") as fh:
            return fh.read()

    def _read_artifact_source(self, artifact_name):
        return self._read_file(os.path.join(ROOT_DIR, "scripts", "artifacts", artifact_name))

    def test_write_lead_text_escapes(self):
        report_obj = ArtifactHtmlReport("XSS")
        report_obj.start_artifact_report(self.temp_dir, "lead_test")
        report_obj.write_lead_text('<script>alert("x")</script>')
        report_obj.end_artifact_report()

        html = self._read_file(os.path.join(self.temp_dir, "lead_test.temphtml"))
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert", html)

    def test_html_escape_false_sanitizes_table_cells(self):
        report_obj = ArtifactHtmlReport("XSS")
        report_obj.start_artifact_report(self.temp_dir, "table_false")
        report_obj.write_artifact_data_table(
            ("A",),
            [('<img src="x" onerror="alert(1)">',)],
            "path",
            write_total=False,
            write_location=False,
            html_escape=False,
        )
        report_obj.end_artifact_report()

        html = self._read_file(os.path.join(self.temp_dir, "table_false.temphtml"))
        self.assertNotIn("onerror", html.lower())

    def test_html_no_escape_columns_are_sanitized(self):
        report_obj = ArtifactHtmlReport("XSS")
        report_obj.start_artifact_report(self.temp_dir, "table_cols")
        report_obj.write_artifact_data_table(
            ("A", "B"),
            [('<a href="javascript:alert(1)">bad</a>', "safe")],
            "path",
            write_total=False,
            write_location=False,
            html_escape=True,
            html_no_escape=["A"],
        )
        report_obj.end_artifact_report()

        html = self._read_file(os.path.join(self.temp_dir, "table_cols.temphtml"))
        self.assertNotIn("javascript:", html.lower())
        self.assertIn('href="#"', html)

    def test_write_raw_html_accepts_only_trusted_html(self):
        report_obj = ArtifactHtmlReport("XSS")
        report_obj.start_artifact_report(self.temp_dir, "raw")
        with self.assertRaises(TypeError):
            report_obj.write_raw_html("<b>unsafe</b>")
        report_obj.write_raw_html(trust_html("<b>safe</b>"))
        report_obj.end_artifact_report()

    def test_logfunc_escapes_dynamic_values(self):
        log_path = os.path.join(self.temp_dir, "screen_output.html")
        ilapfuncs.OutputParameters.screen_output_file_path = log_path
        ilapfuncs.logfunc('<img src=x onerror="alert(1)">')
        html = self._read_file(log_path)
        self.assertNotIn('<img src=x onerror="alert(1)">', html.lower())
        self.assertIn("&lt;img", html)

    def test_logdevinfo_and_write_device_info_escape_dynamic_values(self):
        devinfo_path = os.path.join(self.temp_dir, "devinfo.html")
        ilapfuncs.OutputParameters.screen_output_file_path_devinfo = devinfo_path
        ilapfuncs.logdevinfo('<script>alert(1)</script>')
        ilapfuncs.identifiers = {
            'Cat<script>': {
                'Label" onclick="x': {
                    "value": '<img src=x onerror="alert(1)">',
                    "source_file": '" onmouseover="alert(1)',
                    "artifact": "mod<script>",
                }
            }
        }
        ilapfuncs.write_device_info()
        html = self._read_file(devinfo_path)
        self.assertNotIn("<script>", html.lower())
        self.assertNotIn('<img src=x onerror="alert(1)">', html.lower())
        self.assertNotIn('title="" onmouseover="alert(1)"', html.lower())

    def test_html_media_tag_sanitizes_title_and_style_context(self):
        tag = ilapfuncs.html_media_tag(
            "my.jpg",
            "image/jpeg",
            'max-width:1px;" onerror="alert(1)',
            'x" onmouseover="alert(1)',
        )
        self.assertNotIn('title="x" onmouseover=', tag.lower())
        self.assertNotIn('style="max-width:1px;" onerror=', tag.lower())

    def test_media_to_html_sanitizes_href_src(self):
        root = os.path.join(self.temp_dir, "report_root")
        os.makedirs(root, exist_ok=True)
        report_folder = os.path.join(root, "reports", "_HTML")
        os.makedirs(report_folder, exist_ok=True)
        data_dir = os.path.join(root, "data")
        os.makedirs(data_dir, exist_ok=True)

        file_name = 'evil" onerror="alert(1).jpg'
        file_path = os.path.join(data_dir, file_name)
        with open(file_path, "wb") as fh:
            fh.write(b"dummy")

        html = ilapfuncs.media_to_html(file_name, [file_path], report_folder)
        self.assertIsNone(re.search(r'href="[^"]*"\s+onerror=', html.lower()))

    def test_write_lava_only_log_escapes_dynamic_values(self):
        lava_log_path = os.path.join(self.temp_dir, "lava_log.html")
        ilapfuncs.OutputParameters.screen_output_file_path_lava_only = lava_log_path
        ilapfuncs.lava_only_artifacts = {
            '<img src=x onerror="alert(1)">': [
                {
                    "artifact_name": '<script>alert(1)</script>',
                    "table_name": 'x" onmouseover="alert(1)',
                    "records": "<b>1</b>",
                }
            ]
        }
        ilapfuncs.write_lava_only_log()
        html = self._read_file(lava_log_path)
        self.assertNotIn('<img src=x onerror="alert(1)">', html.lower())
        self.assertNotIn('onmouseover="alert(1)"', html.lower())
        self.assertNotIn("<script>", html.lower())

    def test_report_index_tabs_sanitize_embedded_log_html(self):
        logs_dir = os.path.join(self.temp_dir, "_HTML", "_Script_Logs")
        os.makedirs(logs_dir, exist_ok=True)
        for name in ("DeviceInfo.html", "Screen_Output.html", "ProcessedFilesLog.html"):
            with open(os.path.join(logs_dir, name), "w", encoding="utf8") as fh:
                fh.write('<script>alert(1)</script><p onclick="x">ok</p>')

        report.create_index_html(
            self.temp_dir,
            1,
            "00:00:01",
            "fs",
            "/source",
            "",
            {},
            "",
            False,
        )
        html = self._read_file(os.path.join(self.temp_dir, "_HTML", "index.html"))
        self.assertNotIn('<script>alert(1)</script>', html.lower())
        self.assertNotIn('onclick="x"', html.lower())

    def test_report_contributor_urls_and_logo_mimetype_are_sanitized(self):
        links = report.generate_authors_table_code(
            [("A", "javascript:alert(1)", 'bad" onclick="x', "data:text/html,abc")]
        )
        self.assertNotIn("javascript:", links.lower())
        self.assertNotIn('" onclick=', links.lower())

        table = report.generate_key_val_table_without_headings(
            "",
            [("k", "v")],
            'text/html" onerror="alert(1)',
            "ZGF0YQ==",
        )
        self.assertNotIn("text/html", table.lower())
        self.assertNotIn("onerror", table.lower())

    def test_chat_rendering_protects_script_context_and_dom_sinks(self):
        payload = '</script><script>alert("x")</script>'
        rendered = chat_rendering.render_js_chat(payload)
        self.assertNotIn("</script><script>", rendered.lower())
        self.assertNotIn(".html(", rendered)

    def test_render_chat_escapes_user_content(self):
        df = pd.DataFrame(
            [
                {
                    "data-name": 'Alice<script>alert(1)</script>',
                    "data-time": datetime(2024, 1, 1, 10, 0, 0),
                    "message": '<img src=x onerror="alert(1)">',
                    "content-type": None,
                    "file-path": None,
                    "from_me": 0,
                }
            ]
        )
        rendered = chat_rendering.render_chat(df)
        self.assertNotIn("alice<script>alert(1)</script>", rendered.lower())
        self.assertNotIn('<img src=x onerror="alert(1)">', rendered.lower())

    def test_notifications_helpers_escape_dynamic_values(self):
        self.assertEqual(
            notificationsXI._safe_text('<script>alert(1)</script>'),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        )
        td = notificationsXI._td('x" onmouseover="alert(1)')
        self.assertEqual(td, "<td>x&quot; onmouseover=&quot;alert(1)</td>")

    def test_chatgpt_artifact_uses_column_sanitizer_contract(self):
        source = self._read_artifact_source("chatgpt.py")
        self.assertNotIn("html_escape=False", source)
        self.assertIn("html_no_escape=['Thumbnail']", source)
        self.assertIn("html_no_escape=['Voice Prompt']", source)

    def test_teleguard_artifact_uses_column_sanitizer_contract(self):
        source = self._read_artifact_source("teleguard.py")
        self.assertNotIn("html_escape=False", source)
        self.assertIn("html_no_escape=['Media']", source)
        self.assertIn("html_no_escape=['Avatar']", source)
        self.assertIn("escape_text(values)", source)

    def test_life360_artifact_uses_column_sanitizer_contract(self):
        source = self._read_artifact_source("life360.py")
        self.assertNotIn("html_escape=False", source)
        self.assertIn("html_no_escape=['Avatar URL']", source)
        self.assertIn("sanitize_url(row[5])", source)

    def test_zangi_artifact_avoids_global_html_passthrough(self):
        source = self._read_artifact_source("ZangiChats.py")
        self.assertNotIn("html_escape=False", source)

    def test_oops_artifact_avoids_global_html_passthrough(self):
        source = self._read_artifact_source("Oops.py")
        self.assertNotIn("html_escape=False", source)

    def test_slice_b_owned_artifacts_avoid_global_html_passthrough(self):
        owned_artifacts = (
            "iconsScreen.py",
            "idstatuscache.py",
            "uberClient.py",
            "uberPlaces.py",
            "webClips.py",
            "torrentData.py",
        )
        for artifact in owned_artifacts:
            source = self._read_artifact_source(artifact)
            self.assertNotIn(
                "html_escape=False",
                source,
                msg=f"{artifact} still uses global html_escape=False",
            )

    def test_wave3_owned_artifacts_use_column_sanitizer_contract(self):
        owned_artifacts = (
            "biomeIntents.py",
            "geodApplications.py",
            "geodMapTiles.py",
            "geodPDPlaceCache.py",
            "hikvision.py",
            "icloudMeta.py",
            "icloudPhotoMeta.py",
            "kikBplistmeta.py",
            "mobileInstall.py",
            "notificationsXI.py",
            "walStrings.py",
        )
        for artifact in owned_artifacts:
            source = self._read_artifact_source(artifact)
            self.assertNotIn(
                "html_escape=False",
                source,
                msg=f"{artifact} still uses global html_escape=False",
            )
            self.assertNotIn(
                "html_escape = False",
                source,
                msg=f"{artifact} still uses global html_escape=False",
            )

        rich_columns_by_artifact = {
            "biomeIntents.py": ["Data"],
            "geodMapTiles.py": ["Image"],
            "geodPDPlaceCache.py": ["pd place"],
            "hikvision.py": ["File Content"],
            "kikBplistmeta.py": ["Internal Thumbnail"],
            "mobileInstall.py": ["Report Link"],
            "notificationsXI.py": ["Bundle GUID"],
            "walStrings.py": ["Report"],
        }
        for artifact, columns in rich_columns_by_artifact.items():
            source = self._read_artifact_source(artifact)
            for column in columns:
                self.assertRegex(
                    source,
                    rf"html_no_escape\s*=\s*\[[^\]]*['\"]{re.escape(column)}['\"][^\]]*\]",
                    msg=f"{artifact} missing html_no_escape contract for {column}",
                )

    def test_icons_screen_escapes_dynamic_values_and_keeps_layout(self):
        plist_path = os.path.join(self.temp_dir, "IconState.plist")
        plist_data = {
            "buttonBar": ['<img src=x onerror="alert(2)">'],
            "iconLists": [
                [
                    {
                        "listType": "folder",
                        "displayName": '<img src=x onerror="alert(1)">',
                        "iconLists": [["bad<script>alert(1)</script>"]],
                    }
                ]
            ],
        }
        with open(plist_path, "wb") as fh:
            plistlib.dump(plist_data, fh)

        iconsScreen.get_iconsScreen([plist_path], self.temp_dir, None, False, "UTC")

        html = self._read_file(os.path.join(self.temp_dir, "Apps per screen.temphtml"))
        self.assertIn('display: grid;grid-template-columns', html)
        self.assertNotIn('<img src=x onerror="alert(1)">', html.lower())
        self.assertIn('&lt;img src=x onerror="alert(1)"&gt;', html)
        self.assertIsNone(re.search(r"<[^>]+\\sonerror\\s*=", html.lower()))

    def test_webclips_escapes_title_url_and_sanitizes_image_src(self):
        root = os.path.join(
            self.temp_dir,
            "private",
            "var",
            "mobile",
            "Library",
            "WebClips",
            "clip123.webclip",
        )
        os.makedirs(root, exist_ok=True)
        info_path = os.path.join(root, "Info.plist")
        icon_path = os.path.join(root, "icon.png")
        with open(info_path, "wb") as fh:
            plistlib.dump(
                {
                    "Title": '<img src=x onerror="alert(1)">',
                    "URL": 'javascript:alert(1)" onclick="alert(2)',
                },
                fh,
            )
        with open(icon_path, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        webClips.get_webClips([info_path, icon_path], self.temp_dir, None, False, "UTC")

        html = self._read_file(os.path.join(self.temp_dir, "WebClips.temphtml"))
        self.assertIn('src="data:image/png;base64,', html)
        self.assertNotIn('<img src=x onerror="alert(1)">', html.lower())
        self.assertIn('&lt;img src=x onerror="alert(1)"&gt;', html)
        self.assertIsNone(re.search(r'<img[^>]+src="javascript:', html.lower()))

    def test_torrent_data_uses_sanitized_fragment_contract(self):
        source = self._read_artifact_source("torrentData.py")
        self.assertIn("html_no_escape=['Path']", source)
        self.assertIn("escape_text", source)

    def test_protonmail_attachment_html_sanitizes_url_and_attributes(self):
        html_snippet = protonMail._build_attachment_html(
            'javascript:alert(1)" onerror="alert(1)',
            "video/mp4",
        )
        self.assertIn('src="#"', html_snippet)
        self.assertIsNone(re.search(r'src="[^"]*"\s+onerror=', html_snippet.lower()))
        self.assertIn('type="video/mp4"', html_snippet)

    def test_protonmail_avoids_html_unescape_in_decrypt_flow(self):
        source = self._read_artifact_source("protonMail.py")
        self.assertNotIn("html.unescape(", source)

    def test_voice_recordings_audio_html_quotes_and_sanitizes_src(self):
        html_snippet = voiceRecordings._build_audio_file_html(
            'javascript:alert(1)" onerror="alert(1)'
        )
        self.assertIn('src="#"', html_snippet)
        self.assertIn('<source src="', html_snippet)
        self.assertIsNone(re.search(r'src="[^"]*"\s+onerror=', html_snippet.lower()))

    def test_voice_triggers_audio_html_quotes_and_sanitizes_src(self):
        html_snippet = voiceTriggers._build_audio_file_html(
            'javascript:alert(1)" onerror="alert(1)'
        )
        self.assertIn('src="#"', html_snippet)
        self.assertIn('<source src="', html_snippet)
        self.assertIsNone(re.search(r'src="[^"]*"\s+onerror=', html_snippet.lower()))

    def test_biome_notes_note_html_escapes_text_and_keeps_line_breaks(self):
        html_snippet = biomeNotes._format_note_html("first line\n<img src=x onerror=alert(1)>")
        self.assertIn("first line<br>", html_snippet)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html_snippet)
        self.assertNotIn("<img src=x onerror=alert(1)>", html_snippet.lower())

    def test_calendar_sharees_escape_dynamic_values(self):
        class _Cursor:
            def execute(self, _query):
                return None

            def fetchall(self):
                return [
                    (
                        1,
                        "mailto:attacker@example.com<script>alert(1)</script>",
                        'victim" onmouseover="alert(1)',
                        "View & Edit",
                    )
                ]

        participants = calendarAll.get_sharees(_Cursor())
        self.assertIn("&lt;script&gt;", participants[1])
        self.assertNotIn("<script>", participants[1].lower())
        self.assertNotIn('" onmouseover="alert(1)', participants[1].lower())

    def test_calendar_invitees_escape_dynamic_values(self):
        class _Cursor:
            def execute(self, _query):
                return None

            def fetchall(self):
                return [
                    (
                        1,
                        "<img src=x onerror=alert(1)>",
                        "victim@example.com",
                        "Accepted",
                    )
                ]

        invitees_html, _invitees_csv = calendarAll.get_invitees(_Cursor())
        self.assertIn("<span", invitees_html[1])
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", invitees_html[1])
        self.assertNotIn("<img src=x onerror=alert(1)>", invitees_html[1].lower())

    def test_calendar_name_html_escapes_name_and_style(self):
        calendar_name = calendarAll.get_calendar_name(
            "<b>Critical</b>",
            'red;" onclick="alert(1)',
        )
        self.assertNotIn("<b>", calendar_name.lower())
        self.assertNotIn("onclick", calendar_name.lower())
        self.assertIn("Critical", calendar_name)

    def test_calendar_map_link_sanitizes_href_and_attributes(self):
        tag = calendarAll._build_location_coordinates_tag(
            '41.12" onclick="alert(1)',
            '-87.55" onmouseover="alert(1)',
        )
        self.assertIn('<a href="', tag)
        self.assertIn('target="_blank"', tag)
        self.assertIsNone(re.search(r'href="[^"]*"\s+onclick=', tag.lower()))
        self.assertIsNone(re.search(r'href="[^"]*"\s+onmouseover=', tag.lower()))

    def test_kik_pending_upload_thumbnail_html_sanitizes_src(self):
        html_snippet = kikPendingUploads._build_pending_file_thumb(
            "/tmp/report_folder",
            'javascript:alert(1)" onerror="alert(1)',
        )
        self.assertIn('src="#"', html_snippet)
        self.assertIn('<img src="', html_snippet)
        self.assertIsNone(re.search(r'src="[^"]*"\s+onerror=', html_snippet.lower()))

    def test_repo_scripts_avoid_html_escape_false(self):
        pattern = re.compile(r'html_escape\s*=\s*False')
        offenders = []
        scripts_root = os.path.join(ROOT_DIR, "scripts")

        for root, _dirs, files in os.walk(scripts_root):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                file_path = os.path.join(root, filename)
                source = self._read_file(file_path)
                if pattern.search(source):
                    offenders.append(os.path.relpath(file_path, ROOT_DIR))

        self.assertEqual([], offenders, msg=f"Files still using html_escape=False: {offenders}")

    def test_repo_artifacts_avoid_inline_onclick_handlers(self):
        onclick_pattern = re.compile(r'onclick\s*=')
        offenders = []
        artifacts_root = os.path.join(ROOT_DIR, "scripts", "artifacts")

        for root, _dirs, files in os.walk(artifacts_root):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                file_path = os.path.join(root, filename)
                source = self._read_file(file_path)
                if onclick_pattern.search(source):
                    offenders.append(os.path.relpath(file_path, ROOT_DIR))

        self.assertEqual([], offenders, msg=f"Artifacts still using inline onclick: {offenders}")


if __name__ == "__main__":
    unittest.main()
