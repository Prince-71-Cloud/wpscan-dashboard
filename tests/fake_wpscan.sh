#!/usr/bin/env bash
# Stand-in for the wpscan binary: replays recorded output, never touches the
# network. Behaviour is keyed on --url so one batch can exercise several paths.
url=""; tls=0
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="$2"; shift ;;
    --disable-tls-checks) tls=1 ;;
  esac
  shift
done
here="$(cd "$(dirname "$0")" && pwd)"
fx="$here/fixtures/wpscan_cli_42.txt"
replay() { sed -e "s#https://example.test#$1#g" -e "s#Requests Remaining: 20#Requests Remaining: $2#" "$fx"; }
case "$url" in
  https://redirect.example.test)
    echo "Scan Aborted: The URL supplied redirects to https://www.redirect.example.test/. Use the --ignore-main-redirect option to ignore the redirection and scan the target, or change the --url option value to the redirected URL."
    exit 4 ;;
  https://www.redirect.example.test)
    replay "$url" 20; exit 5 ;;
  https://tls.example.test)
    if [ "$tls" = 1 ]; then replay "$url" 20; exit 5; fi
    echo "Scan Aborted: The url supplied 'https://tls.example.test/' seems to be down (SSL peer certificate or SSH remote key was not OK)"
    exit 4 ;;
  https://quota.example.test)
    replay "$url" 0; exit 5 ;;
  *)
    replay "$url" 20; exit 5 ;;
esac
