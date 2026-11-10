"""Windows Task Scheduler jobs -> CronJob schedules and arguments (schedules.py, generate.k8s_manifests)."""
import textwrap

import yaml

from containerizer import schedules
from containerizer.assess import assess
from containerizer.generate import generate_app, k8s_manifests, make_plan
from containerizer.report import migration_markdown
from containerizer.rules import load_rules
from containerizer.scan import scan
from containerizer.schedules import Trigger, schedule

RULES = load_rules()


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text).lstrip())
    return p


def console(root, name="Acme.Jobs", usage="refunds|reminders|purge"):
    write(root, f"src/{name}/{name}.csproj", """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
        </Project>""")
    body = f'Console.WriteLine("Usage: Jobs <{usage}>");' if usage else 'Console.WriteLine("run");'
    write(root, f"src/{name}/Program.cs", f"""
        using System;
        public static class Program {{
            public static int Main(string[] args) {{
                if (args.Length == 0) {{ {body} return 1; }}
                return 0;
            }}
        }}""")


# A table of jobs registered in a loop; the days of the week in a variable (the PowerShell ScheduledTasks module)
PS_TABLE = """
    param([string]$InstallPath = 'C:\\Apps\\Acme.Jobs')
    $exe = Join-Path $InstallPath 'Acme.Jobs.exe'
    $weekdays = 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'
    # a comment that mentions New-ScheduledTaskTrigger -Daily -At 01:00
    $tasks = @(
        @{ Name = 'Refund export'; Verb = 'refunds';   Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $weekdays -At '06:30' }
        @{ Name = 'Reminders';     Verb = 'reminders'; Trigger = New-ScheduledTaskTrigger -Daily -At '09:00' }
    )
    foreach ($task in $tasks) {
        $action = New-ScheduledTaskAction -Execute $exe -Argument $task.Verb -WorkingDirectory $InstallPath
        Register-ScheduledTask -TaskName $task.Name -Action $action -Trigger $task.Trigger `
            -User 'CORP\\svc' -Force | Out-Null
    }
    """

# One trigger, its repetition copied from a -Once trigger: every 30 minutes for 14 hours
PS_REPEAT = """
    $exe = 'C:\\Apps\\Acme.Jobs\\Acme.Jobs.exe'
    $export = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday, Tuesday, Wednesday, Thursday, Friday -At 06:00
    $export.Repetition = (New-ScheduledTaskTrigger -Once -At 06:00 -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Hours 14)).Repetition
    Register-ScheduledTask -TaskName 'Purge' -Force `
        -Action (New-ScheduledTaskAction -Execute $exe -Argument 'purge') `
        -Trigger $export
    $logon = New-ScheduledTaskTrigger -AtLogOn -User 'CORP\\desk'
    Register-ScheduledTask -TaskName 'Desk' -Action (New-ScheduledTaskAction -Execute 'C:\\Desk\\Desk.exe') -Trigger $logon
    """

CMD = """
    @echo off
    rem schtasks /create /tn Ignored /sc DAILY /st 01:00 /tr "x.exe"
    schtasks /create /tn "Acme\\Reminders" /tr "\\"C:\\Apps\\Acme.Jobs\\Acme.Jobs.exe\\" reminders --all" /sc WEEKLY /d MON,WED,FRI /st 07:15 /ru SYSTEM
    schtasks /create /tn "Acme\\Poll" /tr "C:\\Apps\\Acme.Jobs\\Acme.Jobs.exe refunds" ^
        /sc MINUTE /mo 15 /st 08:00 /du 10:00
    """

XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\\Acme\\Monthly purge</URI></RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T03:00:00</StartBoundary>
      <ScheduleByMonth><DaysOfMonth><Day>1</Day><Day>15</Day></DaysOfMonth></ScheduleByMonth>
    </CalendarTrigger>
    <CalendarTrigger>
      <Repetition><Interval>PT2H</Interval><Duration>PT8H</Duration></Repetition>
      <StartBoundary>2024-01-01T08:00:00</StartBoundary>
      <ScheduleByWeek><DaysOfWeek><Saturday /><Sunday /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>
    </CalendarTrigger>
    <BootTrigger />
  </Triggers>
  <Actions Context="Author"><Exec><Command>dotnet</Command><Arguments>C:\\Apps\\Acme.Jobs\\Acme.Jobs.dll purge</Arguments></Exec></Actions>
</Task>
"""


def by_name(tasks):
    out = {}
    for t in tasks:
        out.setdefault(t["name"], []).append(t)
    return out


def test_cron_of_triggers():
    assert schedule(Trigger("daily", at=(9, 0)))[0] == "0 9 * * *"
    assert schedule(Trigger("weekly", at=(6, 30), days=[1, 2, 3, 4, 5]))[0] == "30 6 * * 1-5"
    assert schedule(Trigger("weekly", at=(6, 0), days=[1, 2, 3, 4, 5], repeat=30, duration=14 * 60))[0] == "*/30 6-19 * * 1-5"
    assert schedule(Trigger("daily", at=(6, 15), repeat=30, duration=120))[0] == "15-59/30 6,7 * * *"
    assert schedule(Trigger("daily", at=(0, 0), repeat=5))[0] == "*/5 * * * *"
    assert schedule(Trigger("daily", at=(6, 15), repeat=60))[0] == "15 * * * *"
    assert schedule(Trigger("monthly", at=(3, 0), monthdays=[1, 15]))[0] == "0 3 1,15 * *"
    assert schedule(Trigger("once", at=(0, 0), repeat=10))[0] == "*/10 * * * *"
    cron, note = schedule(Trigger("daily", at=(1, 0), repeat=45))
    assert cron is None and "45 minutes" in note
    cron, note = schedule(Trigger("logon"))
    assert cron is None and "logon" in note
    assert schedule(Trigger("startup"))[0] is None and schedule(Trigger("once", at=(1, 0)))[0] is None


def test_powershell_table_loop_and_repetition(tmp_path):
    write(tmp_path, "deploy/Register-Jobs.ps1", PS_TABLE)
    write(tmp_path, "deploy/More.ps1", PS_REPEAT)
    tasks = by_name(schedules.find(scan(tmp_path)))
    assert set(tasks) == {"Refund export", "Reminders", "Purge", "Desk"}      # nothing from the comment
    r = tasks["Refund export"][0]
    assert (r["schedule"], r["arguments"], r["line"]) == ("30 6 * * 1-5", ["refunds"], 6)
    assert r["program"].endswith("Acme.Jobs.exe") and r["file"] == "deploy/Register-Jobs.ps1"
    assert tasks["Reminders"][0]["schedule"] == "0 9 * * *"
    p = tasks["Purge"][0]
    assert p["schedule"] == "*/30 6-19 * * 1-5" and p["trigger"] == "weekly Mon-Fri 06:00, every 30 min for 14 h"
    d = tasks["Desk"][0]
    assert d["schedule"] is None and d["kind"] == "logon" and "logon" in d["note"]


def test_schtasks_cmd_and_splatted(tmp_path):
    write(tmp_path, "deploy/install-tasks.cmd", CMD)
    write(tmp_path, "deploy/settings.ps1", """
        $Settings = @{
            Tasks = @(
                @{ Name = 'Nightly'; Program = 'Acme.Jobs\\Acme.Jobs.exe'; Arguments = 'purge'; Schedule = 'DAILY'; At = '22:30' }
                @{ Name = 'Weekly';  Program = 'Acme.Jobs\\Acme.Jobs.exe'; Arguments = 'refunds'; Schedule = 'WEEKLY'; At = '02:00'; Day = 'SUN' }
            )
        }""")
    write(tmp_path, "deploy/Install.ps1", """
        $settings = Get-Settings
        foreach ($task in $settings.Tasks) {
            $program = Join-Path $appsRoot $task.Program
            $command = "`"$program`" $($task.Arguments)"
            $taskArgs = @('/Create', '/F', '/TN', $task.Name, '/TR', $command, '/SC', $task.Schedule, '/ST', $task.At)
            if ($task.ContainsKey('Day')) { $taskArgs += @('/D', $task.Day) }
            & schtasks.exe @taskArgs | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "schtasks could not create '$($task.Name)'." }
        }""")
    tasks = by_name(schedules.find(scan(tmp_path)))
    assert set(tasks) == {"Acme\\Reminders", "Acme\\Poll", "Nightly", "Weekly"}
    rem = tasks["Acme\\Reminders"][0]
    assert rem["schedule"] == "15 7 * * 1,3,5" and rem["arguments"] == ["reminders", "--all"]
    assert rem["program"] == "C:\\Apps\\Acme.Jobs\\Acme.Jobs.exe" and rem["line"] == 3
    assert tasks["Acme\\Poll"][0]["schedule"] == "*/15 8-17 * * *"
    assert tasks["Nightly"][0]["schedule"] == "30 22 * * *" and tasks["Nightly"][0]["arguments"] == ["purge"]
    assert tasks["Weekly"][0]["schedule"] == "0 2 * * 0"


def test_task_scheduler_xml(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "MonthlyPurge.xml").write_bytes(XML.encode("utf-16"))   # as Task Scheduler exports it
    ts = schedules.find(scan(tmp_path))
    assert [t["name"] for t in ts] == ["Monthly purge"] * 3
    assert [t["schedule"] for t in ts] == ["0 3 1,15 * *", "0 8,10,12,14 * * 0,6", None]
    assert ts[0]["program"] == "dotnet" and ts[0]["arguments"][-1] == "purge" and ts[2]["kind"] == "startup"


def cronjobs_of(tmp_path):
    a = assess(tmp_path, RULES)
    c = next(c for c in a.components if c.name == "Acme.Jobs")
    assert c.role == "console"
    docs = k8s_manifests(a, c, make_plan(a, c, RULES), "reg.example/app/jobs:1")
    return a, {d["metadata"]["name"]: d for d in docs if d["kind"] == "CronJob"}


def test_generator_uses_the_schedules(tmp_path):
    console(tmp_path)
    write(tmp_path, "deploy/Register-Jobs.ps1", PS_TABLE)
    a, jobs = cronjobs_of(tmp_path)
    assert set(jobs) == {"acme-jobs-refunds", "acme-jobs-reminders", "acme-jobs-purge"}
    r = jobs["acme-jobs-refunds"]
    assert r["spec"]["schedule"] == "30 6 * * 1-5"
    assert r["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["args"] == ["refunds"]
    assert r["metadata"]["annotations"]["containerizer.io/schedule-source"] == "deploy/Register-Jobs.ps1:6"
    assert "Refund export" in r["_comment"]
    assert jobs["acme-jobs-reminders"]["spec"]["schedule"] == "0 9 * * *"
    # no job starts purge: the placeholder, annotated for review
    p = jobs["acme-jobs-purge"]
    assert p["spec"]["schedule"] == "0 2 * * *"
    assert p["metadata"]["annotations"]["containerizer.io/schedule"] == "placeholder"
    assert "spec" in p and "timeZone" not in p["spec"]
    # the report says what each job became
    st = {t["name"]: t for t in a.scheduled_tasks()}
    assert st["Refund export"]["cronjobs"] == ["acme-jobs-refunds"] and st["Refund export"]["component"] == "Acme.Jobs"
    md = migration_markdown(a)
    assert "## Windows Task Scheduler jobs" in md
    assert "| Refund export | `deploy/Register-Jobs.ps1:6` | weekly Mon-Fri 06:30 | `30 6 * * 1-5` | CronJob " \
           "`acme-jobs-refunds` (Acme.Jobs) |" in md
    assert a.to_dict()["scheduled_tasks"][0]["schedule"] == "30 6 * * 1-5"


def test_several_triggers_and_arguments_without_commands(tmp_path):
    console(tmp_path, usage="")
    write(tmp_path, "deploy/tasks.cmd", """
        schtasks /create /tn A /tr "C:\\Apps\\Acme.Jobs.exe --import" /sc DAILY /st 01:00
        schtasks /create /tn B /tr "C:\\Apps\\Acme.Jobs.exe --export" /sc DAILY /st 05:00
        schtasks /create /tn C /tr "C:\\Apps\\Acme.Jobs.exe --export" /sc WEEKLY /d SAT /st 12:00
        schtasks /create /tn D /tr "C:\\Apps\\Other.exe" /sc DAILY /st 12:00
        """)
    _, jobs = cronjobs_of(tmp_path)
    got = {n: (d["spec"]["schedule"], d["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0].get("args"))
           for n, d in jobs.items()}
    assert got == {"acme-jobs-import": ("0 1 * * *", ["--import"]), "acme-jobs-export": ("0 5 * * *", ["--export"]),
                   "acme-jobs-export-2": ("0 12 * * 6", ["--export"])}


def test_no_task_scheduler_job_keeps_the_placeholder(tmp_path):
    console(tmp_path, usage="")
    _, jobs = cronjobs_of(tmp_path)
    (job,) = jobs.values()
    assert job["spec"]["schedule"] == "0 2 * * *"
    assert job["metadata"]["annotations"] == {"containerizer.io/schedule": "placeholder"}


def test_generated_yaml_and_migration(tmp_path):
    console(tmp_path)
    write(tmp_path, "deploy/Register-Jobs.ps1", PS_TABLE)
    out = tmp_path / "out"
    generate_app(assess(tmp_path, RULES), out, RULES)
    docs = [d for d in yaml.safe_load_all((out / "acme-jobs" / "k8s.yaml").read_text()) if d and d["kind"] == "CronJob"]
    assert {d["metadata"]["name"]: d["spec"]["schedule"] for d in docs} == {
        "acme-jobs-refunds": "30 6 * * 1-5", "acme-jobs-reminders": "0 9 * * *", "acme-jobs-purge": "0 2 * * *"}
    assert "# schedule from the Task Scheduler job Refund export" in (out / "acme-jobs" / "k8s.yaml").read_text()
    assert "CronJob `acme-jobs-reminders`" in (out / "MIGRATION.md").read_text()


def test_results_page_section():
    from containerizer.webui import _scheduled_tasks
    html = _scheduled_tasks([
        {"name": "Refund export", "file": "deploy/a.ps1", "line": 6, "trigger": "weekly Mon-Fri 06:30",
         "schedule": "30 6 * * 1-5", "note": "", "component": "Acme.Jobs", "cronjobs": ["acme-jobs-refunds"]},
        {"name": "Desk <runner>", "file": "deploy/b.ps1", "line": 9, "trigger": "at logon", "schedule": None,
         "note": "runs at logon", "component": None, "cronjobs": [], "why_not": "runs at logon: a Deployment"}])
    assert "<code>30 6 * * 1-5</code>" in html and "CronJob <code>acme-jobs-refunds</code>" in html
    assert "Desk &lt;runner&gt;" in html and "runs at logon: a Deployment" in html
    assert _scheduled_tasks([]) == ""
