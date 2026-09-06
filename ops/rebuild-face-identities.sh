#!/bin/bash
# Repopulate ui_face_identity_data (Protect face-matcher reference index) from
# verified, named samples. Workaround for Protect 7.1.x: ai-feature-console CLEARS
# this table on startup but never rebuilds it -> matcher has no references and every
# face fragments. Idempotent. See memory: project_face_corpus_fragmentation.
set -euo pipefail
sudo -u postgres psql -p 5433 -d smart_detect_face -v ON_ERROR_STOP=1 -c "insert into ui_face_identity_data (subject_id, subject_id_str, subject_name, unique_id, user_id, embed) select distinct on (trim(subject_name)) subject_id, subject_id::text, trim(subject_name), gen_random_uuid()::text, '', embed from ui_face_db where is_verified and coalesce(trim(subject_name),'')<>'' order by trim(subject_name), blurness asc nulls last on conflict (subject_name, user_id) do nothing;"
