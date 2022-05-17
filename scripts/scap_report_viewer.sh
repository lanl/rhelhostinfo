#!/bin/bash
#
# This is a simple script to view a SCAP scorecard which is in HTML
# It looks for the latest versioned report in the directory that
# rhelhostinfo puts the report files in and then spawns firefox to open the
# file.
#

REPORT_DIR=/opt/rhelhostinfo/log/SCAP
report_files="$(ls -vr ${REPORT_DIR}/*html*)"
declare -a report_lists
report_lists=("$report_files")
/usr/bin/firefox -no-remote -private-window file://"${report_lists[0]}"
