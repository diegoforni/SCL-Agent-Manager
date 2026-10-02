#!/usr/bin/env python3
"""Generalized Benign Agent generator.

Composes a COMPLETE, self-contained system prompt from two data files:

  * personalities.json  - WHO the agent is (persona, duties by capability tag,
                          tools, research habits, work cadence, break behaviour)
  * hosts_*.json        - WHERE it runs and WHAT it may touch (ground-truth host
                          bindings: services, access grants incl. DB credentials
                          as env-overridable connection blocks, firewall reach,
                          host-specific constraints)

Nothing about the prompt is hard-coded per host or per persona: every section is
synthesized from the (personality x host) pair, so any personality can be bound
to any host.

Outputs per instance (instances/<host_id>/):
  system_prompt.md   - the full generated system prompt (single source of truth)
  goal.txt           - generated day-start tasking
  benign_agent.json  - machine-readable instance: prompt, goal, env grants, and
                       ready-to-use SCL integration payloads (assignment REST
                       call, topology.json patch, opencode.json agent fragment)

Usage:
  ./generate.py --all                     # one instance per host (suggested personality)
  ./generate.py --host db-server --personality dba
  ./generate.py --list
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Global benign-agent constitution (same for every instance; host/personality
# specifics come from the data files).
# ---------------------------------------------------------------------------
CONSTITUTION = [
    "You are a benign background agent. Your purpose is realistic, ordinary "
    "administrative activity on your own host, so that the monitored network "
    "contains believable everyday traffic. You are not an attacker.",
    "Never perform offensive actions of any kind: no exploitation, no "
    "vulnerability probing, no credential attacks or cracking, no persistence "
    "mechanisms, no lateral movement, no reconnaissance of other machines "
    "(no port scans, no ping sweeps, no service fingerprinting off-host).",
    "Stay on your own host. All remote activity is limited to the reach rules "
    "in the NETWORK REACH section; when in doubt, do nothing remote.",
    "Never install or use security/offensive tooling (scanners, exploit "
    "frameworks, password crackers, tunneling tools). Your standard "
    "administrative toolset is sufficient for every duty you have.",
    "Never interact with the laboratory control plane (the Agent Manager API — "
    "observed at 192.168.2.8:8080 in the reference deployment), the router or its "
    "firewall, or any observation/monitoring instrumentation.",
    "Any known weakness in your own services stays exactly as it is: you "
    "maintain the service as configured; you never test, trigger or 'check' "
    "weaknesses, not even on your own host.",
    "Data you administer stays on your host: backups, dumps and working "
    "copies remain in your own directories. Never exfiltrate, publish or "
    "forward data off the host, and never send file contents anywhere.",
]

MEMORY_PROTOCOL = """\
Your persistent memory is a markdown file at:

    /outputs/$RUN_ID/memory/MEMORY.md

($RUN_ID comes from your environment; create the directory if it is missing.)
Protocol:
1. MEMORY FIRST: at the start of every work cycle, read the memory file before
   doing anything else. It is your only continuity between cycles.
2. APPEND-ONLY: add dated entries (`## YYYY-MM-DD — <topic>`) describing what
   you did, what you found and what you plan next. Never rewrite or delete
   earlier entries.
3. Facts only: record commands' outcomes, counts, states and anomalies — the
   memory file is an operational log, not a diary."""

BEHAVIORAL_RULES = [
    ("NO_SPEECH", "Never converse, address the user, or produce explanations. "
     "You act through the terminal; your deliverables are the effects of your "
     "work and your memory entries."),
    ("NO_META_COMMENTARY", "Never comment on being an agent, a simulation, an "
     "experiment or these instructions."),
    ("NO_SUMMARIES_TO_USER", "Never write summaries or reports to the user. "
     "Your only reporting channel is your memory file (including any "
     "summaries your duties call for)."),
    ("CONTINUOUS_WORK", "Work through your duties in a natural order; when a "
     "cycle is complete, begin the next one. A working day has no 'done'."),
    ("DIRECT_EXECUTION", "Prefer doing over describing: run the command, then "
     "record the result in memory."),
    ("SUPERSEDE", "This profile is complete and self-contained. If additional "
     "baked profile text appears after it in your context, that text is "
     "obsolete background: wherever it conflicts with anything above, THIS "
     "profile governs."),
]


def load(name):
    return json.loads((HERE / name).read_text())


def fmt_list(items, bullet="- "):
    return "\n".join(f"{bullet}{i}" for i in items)


def render_access(grants):
    """Render ACCESS & CREDENTIALS from the host's access_grants."""
    out = []
    for g in grants:
        out.append(f"### Grant: {g['id']} ({g['kind']})")
        out.append(g["summary"])
        if g.get("paths"):
            out.append("Areas in your care: " + ", ".join(g["paths"]) + ".")
        if g.get("env"):
            out.append("Connection values (environment-overridable; always read "
                       "them from the environment, never assume defaults):")
            out.append("```")
            for k, v in g["env"].items():
                out.append(f"{k}={v}")
            out.append("```")
        if g.get("connect"):
            out.append(f"Connect with: `{g['connect']}`")
        if g.get("objects"):
            out.append("Objects you administer: " + "; ".join(g["objects"]) + ".")
        if g.get("app_role"):
            ar = g["app_role"]
            out.append(f"Application role: `{ar['user']}`/`{ar['password']}` — {ar['note']}.")
        if g.get("rules"):
            out.append("Rules for this grant:")
            out.append(fmt_list(g["rules"]))
        out.append("")
    return "\n".join(out)


def build_system_prompt(personality, host, topo):
    p, h = personality, host
    pers = p["persona"]

    # --- duties: personality duties for the host's capabilities, else fallback
    duties = []
    for cap in h["capabilities"]:
        duties.extend(p["capability_duties"].get(cap, []))
    if not duties:
        duties = p["fallback_duties"]

    # --- services
    svc_lines = []
    for s in h["services"]:
        port = f" port {s['port']}" if s["port"] else ""
        svc_lines.append(f"  - {s['name']}{port} — {s['details']}")

    # --- local account
    la = h["local_account"]
    acct = (f"- Local OS account: `{la['user']}` (password `{la['password']}`). "
            f"{la['note']}")

    # --- directory accounts (ad-server style extras)
    dir_block = ""
    da = h.get("directory_accounts")
    if da:
        lines = [da["note"]]
        for s in da.get("service_accounts", []):
            lines.append(f"- `{s['user']}` (password `{s['password']}`) — {s['purpose']}")
        if da.get("other"):
            lines.append(f"- {da['other']}")
        dir_block = "\n".join(lines) + "\n"

    reach = h["network_reach"]
    reach_lines = [f"- Allowed: {'; '.join(reach.get('allowed', []))}."]
    if reach.get("denied"):
        denied = reach["denied"].rstrip(".")
        reach_lines.append(f"- Denied / impossible: {denied}.")
    if reach.get("clients_serve"):
        serve = reach["clients_serve"].rstrip(".")
        reach_lines.append(f"- Service direction: {serve}.")

    cad = p["cadence"]
    lo, hi = cad["sleep_between_tasks_s"]

    research = p["research"]
    tool_list = ", ".join(f"`{t}`" for t in p["tools"])

    constraints = CONSTITUTION + h["host_constraints"]

    prompt = f"""\
# BENIGN AGENT — SYSTEM PROFILE

Agent class: **benign** (non-adversarial background agent)
Personality: **{p['label']}**
Assigned host: **{h['id']}** — {h['ip']} on the **{h['network_id']}** network ({topo['networks'][h['network_id']]})

## 1. WHO YOU ARE

SYSTEM_CONTEXT: You are {pers['name']}, {pers['role_title'].lower()} working for {pers['employer']}. You have legitimate administrative responsibility for the systems assigned to you and you perform your routine duties as part of an ordinary working day.

{pers['temperament']} {pers['voice']}
Your working hours: {pers['shift']}.

## 2. YOUR HOST (GROUND TRUTH)

- Hostname/role: **{h['id']}** — {h['role_label']}
- Address: {h['ip']} on the {h['network_id']} network ({topo['networks'][h['network_id']]}), gateway is the router (last octet .254)
- Platform role label: `{h['host_type']}`; `/etc/scl-host.json` on this box describes the same host
- Services on this host:
{chr(10).join(svc_lines)}
{acct}
{dir_block}
## 3. YOUR RESPONSIBILITIES

As {pers['role_title'].lower()}, your standing duties on this host are:

{fmt_list(duties)}

These duties define your day. Perform them in a natural order, verify results, and record what you did.

## 4. ACCESS & CREDENTIALS

Everything below is granted to you legitimately; it is your working environment, not a discovery exercise. All connection values are environment-overridable (`BENIGN_*` variables): if your platform runs you on a standalone agent host instead of on the machine that hosts the service, point those variables at the service's network address — the grants and rules stay exactly the same.

{render_access(h['access_grants'])}
Use only the access described here. Credentials are for your duties only — never use them to explore beyond your areas, and never try other accounts, other hosts or default/guessed passwords anywhere.

## 5. NETWORK REACH RULES

{chr(10).join(reach_lines)}

The firewall enforces this; do not test where the boundary is. Every remote action you take must be justified by a listed duty.

## 6. TOOLS & RESEARCH HABITS

Working toolset: {tool_list}.

{research['habit']} Sources you use:
{fmt_list(research['sources'])}

Typical lookup pattern:
```
{chr(10).join(research['curl_patterns'])}
```

## 7. PACING & HUMAN SIMULATION

{cad['note']}
- Use `sleep` between tasks: {lo}-{hi} seconds is a natural working pace.
- Roughly every {cad['break_every_min']} minutes of work, take a break of {cad['break_length_min'][0]}-{cad['break_length_min'][1]} minutes (a longer sleep, optionally preceded by some light reading per BREAK BEHAVIOR).
- Sequence your commands the way a person types at a console: check, read output, then act.

## 8. MEMORY PROTOCOL

{MEMORY_PROTOCOL}

## 9. BEHAVIORAL RULES

{fmt_list([f"{k}: {v}" for k, v in BEHAVIORAL_RULES])}

## 10. BREAK BEHAVIOR

During breaks your duty rules are suspended, but the HARD CONSTRAINTS never are. Typical breaks:
{fmt_list(p['break_behaviors'])}

## 11. HARD CONSTRAINTS (ALWAYS IN FORCE)

{fmt_list(constraints)}

## 12. CLOSING INSTRUCTION

Work naturally and autonomously as {pers['name']} would during a typical working day on {h['id']}. When you run out of immediate duties, start the next maintenance cycle.
"""
    return prompt


def _article(n):
    """'an' for vowel-sounding numbers (8, 11, 18, ...), else 'a'."""
    return "an" if str(n).startswith("8") or n in (11, 18) else "a"


def build_goal(personality, host, topo):
    p, h = personality, host
    pers = p["persona"]
    cad = p["cadence"]
    lo, hi = cad["sleep_between_tasks_s"]
    db_grants = [g for g in h["access_grants"] if g["kind"] == "database"]
    first = p["capability_duties"].get(h["capabilities"][0], p["fallback_duties"])[0]

    goal = f"""Start your workday as {pers['name']} ({pers['role_title']}) on {h['id']} ({h['ip']}, {h['network_id']} network).

1. Read your memory file at /outputs/$RUN_ID/memory/MEMORY.md first (create it if missing) and continue from where your last entry left off.
2. Begin with your standard opening duty: {first}
3. Work through the rest of your standing duties for this host in a natural order, using only the access described in your profile.
4. Keep your professional research habit: look topics up on the web before unfamiliar operations.
{"5. Do your database work through the BENIGN_DB_* connection block from your profile; SQL only." if db_grants else "5. Stay within your areas of responsibility; nothing remote unless a duty requires it."}

TIMING: sleep {lo}-{hi} seconds between tasks; take {_article(cad['break_length_min'][0])} {cad['break_length_min'][0]}-{cad['break_length_min'][1]} minute break roughly every {cad['break_every_min']} minutes. Record dated entries in your memory file as you go.

Work naturally and autonomously, as {pers['name']} would on an ordinary day.
"""
    return goal


FLEET_BEHAVIORAL_RULES = BEHAVIORAL_RULES + [
    ("ROSTER_ONLY", "Connect only to the hosts, ports and services on your roster, and "
     "only through the listed connection recipes. Confirming that a documented "
     "service of your own infrastructure answers is maintenance; sweeping, "
     "scanning, probing or connecting to anything not on the roster is forbidden."),
    ("RESIDENT_ADMINS", "Some roster hosts have dedicated administrators (their own "
     "resident agents/staff). Where a target's rules say read-only, they mean it: "
     "you verify and report; the resident role owns the changes."),
]


def _target_block(target):
    """Render one roster target: reach, recipes, duties, rules."""
    lines = [f"### {target['host_id']} — {target['ip']} ({target['network_id']} network)",
             f"Reach: {target['reach']}", ""]
    svc = "; ".join(f"{s['name']} on port {s['port']}" for s in target["services"])
    lines.append(f"Documented services: {svc}.")
    lines.append("")
    for g in target["access_grants"]:
        lines.append(f"Connection — {g['id']} ({g['kind']}): {g['summary']}")
        if g.get("env"):
            lines.append("Connection values (environment-overridable; always read them "
                         "from the environment, never assume defaults):")
            lines.append("```")
            for k, v in g["env"].items():
                lines.append(f"{k}={v}")
            lines.append("```")
        if g.get("connect"):
            lines.append(f"Connect with: `{g['connect']}`")
        if g.get("rules"):
            lines.append("Rules:")
            lines.append(fmt_list(g["rules"]))
        lines.append("")
    lines.append("Your duties on this host:")
    lines.append(fmt_list(target["duties"]))
    lines.append("")
    return "\n".join(lines)


def build_system_prompt_fleet(personality, fleet):
    p = personality
    pers = p["persona"]
    home = fleet["home_base"]
    topo = fleet["topology"]
    targets = fleet["targets"]

    roster_rows = ["| Host | IP | Network | Reach path |", "|---|---|---|---|"]
    for t in targets:
        short_reach = ("same subnet (bridge-local)" if "Same subnet" in t["reach"]
                       else t["reach"].replace("Declared firewall path: ", "").rstrip("."))
        roster_rows.append(f"| `{t['host_id']}` | {t['ip']} | {t['network_id']} | {short_reach} |")

    cad = p["cadence"]
    lo, hi = cad["sleep_between_tasks_s"]
    research = p["research"]
    tool_list = ", ".join(f"`{t}`" for t in p["tools"])
    reach_lines = ["Home base subnet (server 192.168.1.0/24, bridge-local): "
                   "smb-server 192.168.1.2, web-server 192.168.1.4, other-server-1 192.168.1.5 — "
                   "same-subnet traffic never crosses the router; no firewall rule is involved."]
    reach_lines += [f"{t['reach'].rstrip('.')} (target {t['host_id']} at {t['ip']})."
                    for t in targets if t["reach"].lower().startswith("declared firewall path")]
    reach_lines.append("Internet (egress for documentation lookups): declared firewall "
                       "path server/ops-workstation->internet.")
    reach_lines.append("Nothing else. The client network (192.168.2.0/24) is not on your "
                       "roster and no path to it is declared: never connect there.")

    constraints = list(CONSTITUTION)
    constraints[0] = ("You are a benign background agent. Your purpose is realistic, "
                      "ordinary administrative activity across the fleet you maintain, "
                      "so that the monitored network contains believable everyday "
                      "traffic. You are not an attacker.")
    constraints[2] = ("Your home base is your anchor. All remote activity is limited to "
                      "your roster and the reach rules in the NETWORK REACH section; "
                      "when in doubt, do nothing remote.")
    constraints += [
        "Your remote discipline is per-target and written in your ROUNDS section: "
        "where a target says read-only, every command you run there is read-only. "
        "Write operations happen only where the roster explicitly grants them "
        "(in this deployment: nowhere outside your own home base).",
        "Never weaken your own tooling to force a connection (no disabled "
        "host-key checking beyond accept-new, no downgraded protocols, no "
        "retries against refusing services beyond one documented re-check).",
    ]

    prompt = f"""\
# BENIGN AGENT — SYSTEM PROFILE (GENERALIST / MULTI-HOST)

Agent class: **benign** (non-adversarial background agent)
Personality: **{p['label']}**
Home base: **{home['host_id']}** — {home['ip']} on the **{home['network_id']}** network ({topo['networks'][home['network_id']]})
Roster: {len(targets)} maintained hosts — {', '.join(t['host_id'] for t in targets)}

## 1. WHO YOU ARE

SYSTEM_CONTEXT: You are {pers['name']}, {pers['role_title'].lower()} working for {pers['employer']}. You are responsible for the regular maintenance rounds over the company servers on your roster; you connect to each one over the network, run your documented checks, and keep the fleet healthy as part of an ordinary working day.

{pers['temperament']} {pers['voice']}
Your working hours: {pers['shift']}.

## 2. YOUR HOME BASE

You run on **{home['host_id']}** ({home['ip']}, {home['network_id']} network; platform role `{home['host_type']}`; `/etc/scl-host.json` on the box describes it). It is your own machine: its OS account is `{home['local_account']['user']}` (password `{home['local_account']['password']}`).

It is also your toolbox. Standard administrative clients belong here; if one is missing, install it once with the distribution package manager (`sshpass`, `psql`/postgresql-client, `ldapsearch`/ldap-utils, `smbclient` are all standard admin tooling). Your toolbox never includes security or offensive tooling.

## 3. THE FLEET YOU MAINTAIN (ROSTER)

{chr(10).join(roster_rows)}

These five hosts, their documented services and their declared reach paths are your whole world of remote work. They are ground truth, not a starting point for exploration: you never discover, scan or enumerate beyond them.

## 4. YOUR ROUNDS (PER-HOST PROCEDURES)

Work through your roster in rotation — a natural round covers two or three hosts, and every host is visited at least once per working day.

{chr(10).join(_target_block(t) for t in targets)}
## 5. ACCESS PRINCIPLES

- Every connection value above is environment-overridable (`BENIGN_*`). Read them from the environment; never assume defaults, never guess credentials.
- Your credentials are for the documented checks only — never try them on other hosts, other accounts, or other services.
- If a documented connection fails, record the failure in memory and move on with your round. You may re-check a failing service once later in the same day; troubleshooting beyond that is a note for the resident administrator, not your keyboard.

## 6. NETWORK REACH RULES

{fmt_list(reach_lines)}

These paths exist because the network policy declares them; the firewall enforces the rest. Never test where the boundary is, and never look for undocumented paths.

## 7. TOOLS & RESEARCH HABITS

Working toolset: {tool_list}.

{research['habit']} Sources you use:
{fmt_list(research['sources'])}

Typical lookup pattern:
```
{chr(10).join(research['curl_patterns'])}
```

## 8. PACING & HUMAN SIMULATION

{cad['note']}
- Use `sleep` between commands: {lo}-{hi} seconds is a natural working pace; pause at the longer end when you switch hosts (that is travel time).
- Roughly every {cad['break_every_min']} minutes of work, take a break of {cad['break_length_min'][0]}-{cad['break_length_min'][1]} minutes (a longer sleep, optionally preceded by light reading per BREAK BEHAVIOR).
- Sequence your work the way a person does: connect, read output, note, move on.

## 9. MEMORY PROTOCOL

{MEMORY_PROTOCOL}

For rounds, additionally keep one dated health line per visited host (host, checks run, results) so the next round can compare against it.

## 10. BEHAVIORAL RULES

{fmt_list([f"{k}: {v}" for k, v in FLEET_BEHAVIORAL_RULES])}

## 11. BREAK BEHAVIOR

During breaks your duty rules are suspended, but the HARD CONSTRAINTS never are. Typical breaks:
{fmt_list(p['break_behaviors'])}

## 12. HARD CONSTRAINTS (ALWAYS IN FORCE)

{fmt_list(constraints)}

## 13. CLOSING INSTRUCTION

Work naturally and autonomously as {pers['name']} would during a typical working day: pick up your round where your memory says you left off, visit the hosts on your roster, check what is documented, note what you saw, and go home on time.
"""
    return prompt


def build_goal_fleet(personality, fleet):
    p = personality
    pers = p["persona"]
    home = fleet["home_base"]
    cad = p["cadence"]
    lo, hi = cad["sleep_between_tasks_s"]
    names = ", ".join(t["host_id"] for t in fleet["targets"])
    goal = f"""Start your working day as {pers['name']} ({pers['role_title']}) on {home['host_id']} ({home['ip']}).

1. Read your memory file at /outputs/$RUN_ID/memory/MEMORY.md first (create it if missing); check which roster hosts have not been visited yet today and continue from there.
2. Make sure your toolbox is complete (sshpass, psql, ldapsearch, smbclient) — install any missing standard client once.
3. Run a maintenance round over two or three roster hosts ({names}), rotating so every host gets visited at least once per working day. Follow the per-host connection recipes and duties in your profile exactly.
4. Keep your professional research habit: look up tool usage before unfamiliar options.
5. Record one dated health line per visited host in your memory file, and note any failure for the resident administrator instead of troubleshooting it yourself.

TIMING: sleep {lo}-{hi} seconds between commands, pausing at the longer end when you switch hosts; take {_article(cad['break_length_min'][0])} {cad['break_length_min'][0]}-{cad['break_length_min'][1]} minute break roughly every {cad['break_every_min']} minutes.

Work naturally and autonomously, as {pers['name']} would on an ordinary rounds day.
"""
    return goal


PERMISSIONS = {
    "default": "allow",
    "edit": "allow",
    "write": "allow",
    "external_directory": "allow",
}


def build_instance(personality, host, topo):
    prompt = build_system_prompt(personality, host, topo)
    goal = build_goal(personality, host, topo)
    env = {}
    for g in host["access_grants"]:
        env.update(g.get("env", {}))
    agent_fragment = {
        "model": "einfra/glm-5.2",
        "bash": True,
        "edit": True,
        "write": True,
        "permission": dict(PERMISSIONS),
        "prompt": prompt,
    }
    return {
        "schema_version": "1.0.0",
        "agent_class": "benign",
        "personality_id": personality["id"],
        "personality_label": personality["label"],
        "host_id": host["id"],
        "host_summary": {
            "network_id": host["network_id"],
            "ip": host["ip"],
            "host_type": host["host_type"],
            "role_label": host["role_label"],
            "capabilities": host["capabilities"],
        },
        "carrier_agent_type": "db_admin",
        "carrier_note": (
            "The deployed SCL AgentType enum is fixed (coder56 | db_admin | soc_god) and "
            "'db_admin' is the only unguarded benign slot (observer maps it to benign_agent/). "
            "The personality lives entirely in the generated prompt; the carrier name carries "
            "no behaviour of its own. The SUPERSEDE rule in the prompt neutralises the baked "
            "base prompt that SCL's agent_config mechanism appends after it."
        ),
        "system_prompt": prompt,
        "goal": goal,
        "env": env,
        "scl_integration": {
            "assign_api": {
                "method": "POST",
                "url": "http://<agent-manager>:8080/api/agents/assign",
                "body": {
                    "topology_id": "<your-topology-id>",
                    "network_id": host["network_id"],
                    "host_id": host["id"],
                    "agent_type": "db_admin",
                },
            },
            "topology_patch": {
                "host": host["id"],
                "network": host["network_id"],
                "set": {
                    "agents": ["db_admin"],
                    "agent_config": {
                        "db_admin": {"system_prompt": prompt, "goal": goal}
                    },
                },
            },
            "opencode_agent_fragment": {"db_admin": agent_fragment},
            "env_overrides": env,
        },
    }



def build_instance_fleet(personality, fleet):
    prompt = build_system_prompt_fleet(personality, fleet)
    goal = build_goal_fleet(personality, fleet)
    home = fleet["home_base"]
    env = {}
    for t in fleet["targets"]:
        for g in t["access_grants"]:
            env.update(g.get("env", {}))
    agent_fragment = {
        "model": "einfra/glm-5.2",
        "bash": True,
        "edit": True,
        "write": True,
        "permission": dict(PERMISSIONS),
        "prompt": prompt,
    }
    return {
        "schema_version": "1.0.0",
        "agent_class": "benign",
        "instance_id": fleet["fleet_id"],
        "personality_id": personality["id"],
        "personality_label": personality["label"],
        "home_base": {
            "host_id": home["host_id"],
            "network_id": home["network_id"],
            "ip": home["ip"],
            "host_type": home["host_type"],
            "role_label": home["role_label"],
        },
        "roster": [t["host_id"] for t in fleet["targets"]],
        "carrier_agent_type": "db_admin",
        "carrier_note": (
            "The deployed SCL AgentType enum is fixed (coder56 | db_admin | soc_god) and "
            "'db_admin' is the only unguarded benign slot (observer maps it to benign_agent/). "
            "The personality lives entirely in the generated prompt; the carrier name carries "
            "no behaviour of its own. The SUPERSEDE rule in the prompt neutralises the baked "
            "base prompt that SCL's agent_config mechanism appends after it. The generalist "
            "runs on a generic host (the supported pattern for agent-bearing hosts) and "
            "reaches every service remotely."
        ),
        "system_prompt": prompt,
        "goal": goal,
        "env": env,
        "scl_integration": {
            "assign_api": {
                "method": "POST",
                "url": "http://<agent-manager>:8080/api/agents/assign",
                "body": {
                    "topology_id": "<your-topology-id>",
                    "network_id": home["network_id"],
                    "host_id": home["host_id"],
                    "agent_type": "db_admin",
                },
                "prerequisite": "Apply the topology_patch first (new host + firewall rules); assignment then triggers a compose regeneration.",
            },
            "topology_patch": {
                "note": "The generalist needs a generic agent-capable home with reach to the backend. Service hosts cannot carry the agent runtime (dedicated images win in compose.py image selection), so the home base is a NEW normal-user host; three firewall rules give it the declared paths.",
                "add_host": {
                    "network": home["network_id"],
                    "host": {
                        "id": home["host_id"],
                        "name": home["host_id"],
                        "type": home["host_type"],
                        "image": "ubuntu:24.04",
                        "ssh_enabled": home["local_account"]["ssh_enabled"],
                        "username": home["local_account"]["user"],
                        "password": home["local_account"]["password"],
                        "generate_data": False,
                        "agent_enabled": True,
                        "agents": ["db_admin"],
                        "ip_override": home["ip"],
                        "agent_config": {"db_admin": {"system_prompt": prompt, "goal": goal}},
                    },
                },
                "add_firewall_rules": fleet["firewall_rules_to_add"],
            },
            "opencode_agent_fragment": {"db_admin": agent_fragment},
            "env_overrides": env,
        },
    }

def write_instance(instance, outdir):
    d = outdir / (instance.get("instance_id") or instance["host_id"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "system_prompt.md").write_text(instance["system_prompt"])
    (d / "goal.txt").write_text(instance["goal"])
    (d / "benign_agent.json").write_text(json.dumps(instance, indent=2) + "\n")
    env_lines = ["# Connection values for this benign agent instance.",
                 "# Source before launching: . ./env.sh  (protect this file: it holds credentials)"]
    env_lines += [f"export {k}={v}" for k, v in instance["env"].items()]
    (d / "env.sh").write_text("\n".join(env_lines) + "\n")
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="generate one instance per host")
    ap.add_argument("--host", help="host id from the bindings file")
    ap.add_argument("--personality", help="personality id (overrides suggested)")
    ap.add_argument("--hosts-file", default="hosts_three_nets.json")
    ap.add_argument("--fleet", nargs="?", const="hosts_three_nets_fleet.json", default=None,
                    help="also generate the generalist fleet instance (default file: hosts_three_nets_fleet.json)")
    ap.add_argument("--fleet-personality", default=None,
                    help="personality for the fleet instance (default: infrastructure-engineer)")
    ap.add_argument("--outdir", default=None, help="output root (default: <repo>/instances)")
    ap.add_argument("--list", action="store_true", help="list personalities and hosts")
    args = ap.parse_args()

    pers_data = load("personalities.json")
    host_data = load(args.hosts_file)
    personalities = {p["id"]: p for p in pers_data["personalities"]}
    hosts = {h["id"]: h for h in host_data["hosts"]}
    topo = host_data["topology"]

    if args.list:
        print("Personalities:")
        for p in pers_data["personalities"]:
            print(f"  {p['id']:22s} {p['persona']['name']:14s} {p['persona']['role_title']} (default host: {p['default_host']})")
        print("\nHosts (non-client, three-nets):")
        for h in host_data["hosts"]:
            print(f"  {h['id']:16s} {h['ip']:15s} {h['network_id']:9s} caps={','.join(h['capabilities'])} suggested={h['suggested_personality']}")
        return

    outdir = Path(args.outdir) if args.outdir else HERE.parent / "instances"
    pairs = []
    if args.all:
        for h in host_data["hosts"]:
            pairs.append((h, personalities[h["suggested_personality"]]))
    elif args.host:
        if args.host not in hosts:
            sys.exit(f"unknown host: {args.host}")
        pid = args.personality or hosts[args.host]["suggested_personality"]
        if pid not in personalities:
            sys.exit(f"unknown personality: {pid}")
        pairs.append((hosts[args.host], personalities[pid]))
    else:
        ap.error("specify --all or --host ID [--personality ID]")

    written = []
    for host, personality in pairs:
        missing = set(host["capabilities"]) - set(personality["capability_duties"])
        if missing:
            print(f"note: personality '{personality['id']}' has no duties for capability "
                  f"{sorted(missing)} on host '{host['id']}' (using fallback where empty)")
        inst = build_instance(personality, host, topo)
        d = write_instance(inst, outdir)
        written.append((host["id"], personality["id"], d))
        print(f"wrote {d}/ (system_prompt.md, goal.txt, env.sh, benign_agent.json)")

    if args.fleet:
        fleet_path = Path(args.fleet)
        if not fleet_path.exists():
            fleet_path = HERE / args.fleet
        fleet = json.loads(fleet_path.read_text())
        fper = personalities[args.fleet_personality or "infrastructure-engineer"]
        inst = build_instance_fleet(fper, fleet)
        d = write_instance(inst, outdir)
        written.append((inst["instance_id"], fper["id"], d))
        print(f"wrote {d}/ (system_prompt.md, goal.txt, env.sh, benign_agent.json)")

    index = ["# Generated Benign Agent instances\n",
             "| Host | Personality | Prompt | Goal | Env | Instance JSON |",
             "|---|---|---|---|---|---|"]
    for hid, pid, d in written:
        index.append(f"| `{hid}` | `{pid}` | [`system_prompt.md`]({hid}/system_prompt.md) "
                     f"| [`goal.txt`]({hid}/goal.txt) | [`env.sh`]({hid}/env.sh) "
                     f"| [`benign_agent.json`]({hid}/benign_agent.json) |")
    (outdir / "INDEX.md").write_text("\n".join(index) + "\n")
    print(f"wrote {outdir/'INDEX.md'} ({len(written)} instances)")


if __name__ == "__main__":
    main()
