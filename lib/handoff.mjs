/**
 * The hand-off target: a directory that is about to be given to someone else.
 *
 * Static and read-only like everything else here -- it reads NAMES and SIZES through the same
 * injected io layer the other probes use, never a file's contents, and never the network. That
 * limit is the one a caller should understand before trusting it: a key pasted into notes.txt, or
 * a password in a spreadsheet, is invisible to a name match, and each check says so in its own
 * `does_not_cover` rather than leaving it to this comment.
 */
import path from "node:path";
import { readText, parseTorrc, parsePrefs, probeInputsFor } from "./shared.mjs";
import { evaluateBuiltins } from "./checks.mjs";

export const HANDOFF_SCHEMA = "aragami-handoff/1";

/**
 * The probe context for a hand-off scan.
 *
 * An optional Tor install contributes its bases. That is the whole of the integration with onion
 * client authorization: those checks are declared for this target too and are base-gated, so with
 * no install -- or an install whose torrc names no ClientOnionAuthDir -- they return nothing. No
 * id list, no filtering and no special case, which is the point of having made them data.
 */
export function handoffProbeContext(root, torInstall = null) {
  const bases = { handoff_root: root };
  let entries = null;
  let prefs = null;
  if (torInstall && torInstall.data_dir) {
    const torrc = parseTorrc(readText(path.join(torInstall.data_dir, "torrc")));
    const defaults = parseTorrc(readText(path.join(torInstall.data_dir, "torrc-defaults")));
    prefs = parsePrefs(readText(path.join(torInstall.profile_dir ?? "", "prefs.js")));
    entries = { ...defaults.entries, ...torrc.entries };
    bases.install_root = torInstall.root;
    bases.data_dir = torInstall.data_dir;
    bases.profile_dir = torInstall.profile_dir;
    bases.keys_dir = path.join(torInstall.data_dir, "keys");
    const authDir = (entries.ClientOnionAuthDir ?? [])[0];
    if (authDir) bases.auth_dir = authDir;
  }
  return probeInputsFor(root, bases, { entries, prefs });
}

/** Every hand-off finding for one directory, in catalog order. */
export function handoffFindings(root, torInstall = null) {
  if (typeof root !== "string" || !root) return [];
  return evaluateBuiltins("handoff", handoffProbeContext(root, torInstall));
}
