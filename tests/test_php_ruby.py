"""PHP and Ruby: scanning, roles, findings, build plans, Dockerfiles and manifests (issue #254)."""
import hashlib
import json

from containerizer.assess import assess
from containerizer.generate import buildable, dockerfile_for, generate_app, k8s_manifests, make_plan
from containerizer.harden import lint_dockerfile, lint_manifests, load_yaml_docs
from containerizer.scan import scan
from containerizer.scan_php_ruby import parse_gemfile, php_range
from tests.php_ruby_fixtures import laravel, rails, sidekiq_worker, sinatra, wordpress
from tests.test_engine import write


def only(a):
    assert len(a.components) == 1, [(c.name, c.role) for c in a.components]
    return a.components[0]


def ids(c):
    return {f.rule.id for f in c.findings if not f.dormant}


def tree_digest(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def gate_errors(out):
    errs = []
    for cdir in out.iterdir():
        if (cdir / "Dockerfile").exists():
            errs += [v for v in lint_dockerfile((cdir / "Dockerfile").read_text()) if v.severity == "error"]
            errs += [v for v in lint_manifests(load_yaml_docs((cdir / "k8s.yaml").read_text())) if v.severity == "error"]
    return errs


# ------------------------------------------------------------------ scanning

def test_php_constraints():
    assert php_range("^7.4|^8.0") == ("7.4", "8")
    assert php_range(">=7.2") == ("7.2", None)
    assert php_range("~8.2.0") == ("8.2", "8.2")
    assert php_range(">=7.4 <8.3") == ("7.4", "8.2")
    assert php_range("") == (None, None)


def test_gemfile_groups():
    gems, dev = parse_gemfile('gem "rails"\ngroup :development, :test do\n  gem "rspec"\nend\n'
                              'gem "pry", group: :development\ngem "pg"\n')
    assert set(gems) == {"rails", "rspec", "pry", "pg"} and dev == {"rspec", "pry"}


def test_composer_project_scan(tmp_path):
    laravel(tmp_path)
    p = next(p for p in scan(tmp_path).projects if p.kind_hint == "php")
    assert p.properties["Framework"] == "laravel" and p.properties["DocRoot"] == "public"
    assert p.properties["PhpVersion"] == "8.1" and p.properties["PhpVersionMax"] == "8"
    # ext-* of the app and of its locked packages
    assert {"gd", "mbstring", "fileinfo"} <= set(p.properties["PhpExtensions"].split(","))
    assert p.packages["laravel/framework"] == "v10.48.4" and "phpunit/phpunit" in p.dev_packages


def test_locked_package_caps_php_line(tmp_path):
    laravel(tmp_path)
    lock = json.loads((tmp_path / "composer.lock").read_text())
    lock["packages"].append({"name": "old/lib", "version": "1.0.0", "require": {"php": ">=7.3 <8.3"}})
    (tmp_path / "composer.lock").write_text(json.dumps(lock))
    laravel_comp = only(assess(tmp_path))
    assert laravel_comp.project.properties["PhpVersionMax"] == "8.2"
    assert make_plan(assess(tmp_path), laravel_comp)["php"] == "8.2"


def test_plain_php_site_and_wordpress_core_are_one_project(tmp_path):
    wordpress(tmp_path)
    projects = [p for p in scan(tmp_path).projects if p.kind_hint == "php"]
    assert len(projects) == 1                         # not wp-admin/ or wp-content/ again
    assert projects[0].properties["Framework"] == "wordpress"
    assert projects[0].properties["WordPressVersion"] == "6.4.3"


def test_composer_packages_in_vendor_are_not_projects(tmp_path):
    laravel(tmp_path)
    write(tmp_path, "vendor/guzzlehttp/guzzle/composer.json", '{"name": "guzzlehttp/guzzle", "type": "library"}')
    write(tmp_path, "vendor/acme/x/index.php", "<?php\n")
    assert len([p for p in scan(tmp_path).projects if p.kind_hint == "php"]) == 1


def test_gemfile_scan(tmp_path):
    rails(tmp_path)
    p = next(p for p in scan(tmp_path).projects if p.kind_hint == "ruby")
    assert p.properties["Framework"] == "rails" and p.properties["RubyExact"] == "3.2.2"
    assert p.properties["BundlerVersion"] == "2.5.6" and p.properties["LockPlatforms"] == "x86_64-linux"
    assert p.packages["pg"] == "1.5.6" and "rspec-rails" in p.dev_packages and "pg" not in p.dev_packages


# ------------------------------------------------------------------ roles and findings

def test_roles(tmp_path):
    for i, (make, kind, role) in enumerate([(laravel, "php", "web"), (wordpress, "php", "web"), (rails, "ruby", "web"),
                                            (sinatra, "ruby", "web"), (sidekiq_worker, "ruby", "worker")]):
        d = tmp_path / str(i)
        make(d)
        c = only(assess(d))
        assert (c.project.kind_hint, c.role) == (kind, role), make.__name__


def test_libraries_and_tools_are_not_deployed(tmp_path):
    write(tmp_path, "lib/composer.json", '{"name": "acme/lib", "type": "library", "require": {"php": "^8.2"}}')
    write(tmp_path, "plugin/composer.json", '{"name": "acme/seo", "type": "wordpress-plugin"}')
    write(tmp_path, "gem/Gemfile", 'source "https://rubygems.org"\ngemspec\n')
    write(tmp_path, "gem/acme.gemspec", 'Gem::Specification.new { |s| s.name = "acme" }\n')
    write(tmp_path, "docs/Gemfile", 'source "https://rubygems.org"\ngem "jekyll"\n')
    a = assess(tmp_path)
    assert a.components == []


def test_findings_and_ratings(tmp_path):
    laravel(tmp_path / "l")
    wordpress(tmp_path / "w")
    rails(tmp_path / "r")
    sinatra(tmp_path / "s")
    al, aw, ar, as_ = (assess(tmp_path / x) for x in "lwrs")
    assert ids(only(al)) == {"php-laravel-local-disk"} and al.rating == "B"       # stateful: storage/app
    assert ids(only(aw)) == {"php-wordpress-uploads", "php-iis-web-config"} and aw.rating == "B"
    assert ids(only(ar)) == {"ruby-eol-version", "ruby-activestorage-disk"} and ar.rating == "B"
    assert ids(only(as_)) == set() and as_.rating == "A"


def test_windows_only_extensions_and_gems(tmp_path):
    laravel(tmp_path / "p", {"ext-com_dotnet": "*"})
    write(tmp_path / "p", "app/Office.php", "<?php\n$word = new COM('Word.Application');\n")
    sinatra(tmp_path / "r")
    write(tmp_path / "r", "excel.rb", "require 'win32ole'\nxl = WIN32OLE.new('Excel.Application')\n")
    cp, cr = only(assess(tmp_path / "p")), only(assess(tmp_path / "r"))
    assert "php-windows-extensions" in ids(cp) and cp.verdict == "rewrite"
    assert "ruby-windows-gems" in ids(cr) and cr.verdict == "rewrite"


def test_vendor_and_tests_do_not_raise_findings(tmp_path):
    laravel(tmp_path)
    write(tmp_path, "vendor/acme/win/src/Com.php", "<?php\n$x = new COM('X.Y');\n")
    write(tmp_path, "tests/Unit/LegacyTest.php", "<?php\nmysql_connect('x');\n")
    assert not ids(only(assess(tmp_path))) & {"php-windows-extensions", "php-removed-functions"}


# ------------------------------------------------------------------ generation

def test_laravel_image_and_manifests(tmp_path):
    laravel(tmp_path)
    a = assess(tmp_path)
    c = only(a)
    assert buildable(c)
    plan = make_plan(a, c)
    df = dockerfile_for(plan, c)
    assert plan["php"] == "8.4" and plan["uid"] == 33 and plan["port"] == 8080
    assert "FROM php:8.4-apache-bookworm AS base" in df
    assert "install-php-extensions bcmath gd intl opcache pdo_mysql pdo_pgsql zip" in df    # builtins left out
    assert "Listen 8080" in df and "DocumentRoot /var/www/html/public" in df and "FallbackResource /index.php" in df
    assert "composer install --no-dev" in df and "USER 33" in df and 'CMD ["apache2-foreground"]' in df
    assert plan["env"]["LOG_CHANNEL"] == "stderr" and plan["env"]["APP_ENV"] == "production"
    assert {"APP_KEY", "DB_PASSWORD"} <= set(c.facts["secret_settings"])
    docs = k8s_manifests(a, c, plan, "registry.local/x:1")
    pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    ct = pod["containers"][0]
    assert ct["securityContext"]["readOnlyRootFilesystem"] and pod["securityContext"]["runAsUser"] == 33
    mounts = {m["mountPath"] for m in ct["volumeMounts"]}
    assert {"/var/www/html/storage/framework/views", "/var/www/html/bootstrap/cache", "/var/run/apache2",
            "/var/www/html/storage/app"} <= mounts
    claims = [v for v in pod["volumes"] if "persistentVolumeClaim" in v]
    assert len(claims) == 1 and any(d["kind"] == "PersistentVolumeClaim" for d in docs)    # storage/app only
    assert {e["name"] for e in ct["env"] if "valueFrom" in e} >= {"APP_KEY", "DB_PASSWORD"}


def test_wordpress_gets_env_config_without_touching_the_repo(tmp_path):
    wordpress(tmp_path / "app")
    before = tree_digest(tmp_path / "app")
    a = assess(tmp_path / "app")
    out = tmp_path / "out"
    generate_app(a, out)
    assert tree_digest(tmp_path / "app") == before                  # no file of the application changed
    assert gate_errors(out) == []
    df = next(out.glob("*/Dockerfile")).read_text()
    assert "COPY <<'EOF' /var/www/html/wp-config.php" in df and "WORDPRESS_DB_PASSWORD" in df
    assert "install-php-extensions exif gd intl mysqli opcache zip" in df
    assert "composer" not in df                                     # no composer.json: nothing to install
    k8s = next(out.glob("*/k8s.yaml")).read_text()
    assert "/var/www/html/wp-content/uploads" in k8s and "PersistentVolumeClaim" in k8s


def test_wordpress_own_config_is_kept(tmp_path):
    wordpress(tmp_path, config=True)
    a = assess(tmp_path)
    c = only(a)
    assert "wp_config" not in make_plan(a, c) and "WORDPRESS_DB_PASSWORD" not in (c.facts.get("secret_settings") or [])


def test_old_php_runs_on_its_own_line(tmp_path):
    write(tmp_path, "index.php", "<?php\n$c = mysql_connect('db', 'u', 'p');\nmysql_select_db('shop', $c);\n")
    a = assess(tmp_path)
    c = only(a)
    assert "php-removed-functions" in ids(c) and c.verdict == "config"
    plan = make_plan(a, c)
    df = dockerfile_for(plan, c)
    assert plan["php"] == "5.6" and "FROM php:5.6-apache AS base" in df and "install-php-extensions mysql opcache" in df
    assert "FallbackResource" not in df                              # a plain site keeps its URLs


def test_composer_constraint_picks_newest_allowed_line(tmp_path):
    write(tmp_path, "composer.json", '{"require": {"php": "~7.4.0", "slim/slim": "^3.12"}}')
    write(tmp_path, "public/index.php", "<?php\n")
    a = assess(tmp_path)
    c = only(a)
    assert "php-eol-version" in ids(c)
    plan = make_plan(a, c)
    assert plan["php"] == "7.4" and "php:7.4-apache-bullseye" in dockerfile_for(plan, c)


def test_rails_image_and_manifests(tmp_path):
    rails(tmp_path / "app", gems='gem "sidekiq"\ngem "sprockets-rails"')
    before = tree_digest(tmp_path / "app")
    a = assess(tmp_path / "app")
    c = only(a)
    plan = make_plan(a, c)
    df = dockerfile_for(plan, c)
    # Bundler insists on the Gemfile's exact Ruby
    assert plan["ruby_image"] == "ruby:3.2.2-slim" and df.count("FROM ruby:3.2.2-slim") == 2
    assert "libpq-dev" in df and "libpq5" in df and "libvips42" in df and "tzdata" in df
    assert "gem install bundler -v 2.5.6" in df and "bundle config set --local deployment true" in df
    assert "assets:precompile" in df and "USER 65532" in df
    assert 'ENTRYPOINT ["bundle", "exec", "puma", "-C", "config/puma.rb"]' in df
    assert plan["env"]["RAILS_ENV"] == "production" and plan["env"]["PORT"] == "8080"
    assert {"SECRET_KEY_BASE", "DATABASE_URL", "RAILS_MASTER_KEY"} <= set(c.facts["secret_settings"])
    out = tmp_path / "out"
    generate_app(a, out)
    assert tree_digest(tmp_path / "app") == before
    assert gate_errors(out) == []
    docs = load_yaml_docs(next(out.glob("*/k8s.yaml")).read_text())
    deps = [d for d in docs if d["kind"] == "Deployment"]
    assert len(deps) == 2                                             # web + its Sidekiq process
    worker = next(d for d in deps if d["metadata"]["name"].endswith("-sidekiq"))
    wct = worker["spec"]["template"]["spec"]["containers"][0]
    assert wct["command"] == ["bundle"] and wct["args"] == ["exec", "sidekiq"] and "ports" not in wct
    assert worker["spec"]["template"]["spec"]["securityContext"]["runAsNonRoot"]
    ignore = next(out.glob("*/Dockerfile.dockerignore")).read_text()
    assert "**/bin/\n" not in ignore                                  # Rails binstubs stay in the context


def test_windows_lockfile_gets_linux_platform_in_the_build(tmp_path):
    rails(tmp_path)
    lock = (tmp_path / "Gemfile.lock").read_text().replace("  x86_64-linux", "  x64-mingw-ucrt")
    (tmp_path / "Gemfile.lock").write_text(lock)
    a = assess(tmp_path)
    df = dockerfile_for(make_plan(a, only(a)), only(a))
    assert "bundle lock --add-platform ruby x86_64-linux aarch64-linux" in df


def test_sinatra_and_worker(tmp_path):
    sinatra(tmp_path / "s")
    sidekiq_worker(tmp_path / "w")
    a, w = assess(tmp_path / "s"), assess(tmp_path / "w")
    plan = make_plan(a, only(a))
    assert plan["cmd"] == ["bundle", "exec", "puma", "-b", "tcp://0.0.0.0:8080"] and plan["ruby"] == "3.4"
    wplan = make_plan(w, only(w))
    assert wplan["cmd"] == ["bundle", "exec", "sidekiq", "-r", "./worker.rb"] and not wplan["port"]
    out = tmp_path / "out"
    generate_app(w, out)
    assert gate_errors(out) == []
    assert not any(d["kind"] == "Service" for d in load_yaml_docs(next(out.glob("*/k8s.yaml")).read_text()))


def test_symfony_keeps_env_and_bin(tmp_path):
    write(tmp_path, "composer.json", '{"require": {"php": ">=8.2", "symfony/framework-bundle": "7.1.*", "symfony/runtime": "7.1.*"}}')
    write(tmp_path, "public/index.php", "<?php\nuse App\\Kernel;\n")
    write(tmp_path, "bin/console", "#!/usr/bin/env php\n<?php\n")
    write(tmp_path, ".env", "APP_ENV=dev\nAPP_SECRET=\nDATABASE_URL=\"postgresql://app:pw@127.0.0.1:5432/app\"\n")
    a = assess(tmp_path)
    out = tmp_path / "out"
    generate_app(a, out)
    ignore = next(out.glob("*/Dockerfile.dockerignore")).read_text()
    assert "**/.env\n" not in ignore and "**/bin/\n" not in ignore
    df = next(out.glob("*/Dockerfile")).read_text()
    assert 'APP_ENV="prod"' in df and "/var/www/html/var/cache" in df
    assert gate_errors(out) == []
