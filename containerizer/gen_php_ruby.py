"""Facts, build plans and Dockerfiles for PHP and Ruby web applications and workers.

PHP: the official PHP Apache image of the newest supported line composer.json allows (mod_php, so the
app's .htaccess rules keep working), the extensions the app and its locked packages need, Composer in a
build stage, Apache started as www-data (33) on 8080. The application files stay owned by root, so the
image is read-only to the app; only the folders it writes (Laravel storage/, WordPress uploads, ...) are
volumes.

Ruby: Bundler installs the bundle (without development and test) in a build stage that has a compiler
and the -dev packages of the native gems; the slim image of the app's Ruby runs Puma (or the server in
the bundle) as uid 65532 with the native gems' runtime libraries.

Configuration is overridden with environment variables where the framework reads them (Laravel and
Rails read variables over .env / database.yml; WordPress without a wp-config.php gets one in the image
that reads WORDPRESS_DB_*, as the official WordPress image does). No file of the application is changed.
"""
from __future__ import annotations

import json
import re

PHP_ROOT = "/var/www/html"
RUBY_ROOT = "/app"
CA_ENV = "if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca COMPOSER_CAFILE=/run/secrets/ca; fi"

# compiled into the official PHP images (php -m): nothing to install
PHP_BUILTIN = {"core", "ctype", "curl", "date", "dom", "fileinfo", "filter", "ftp", "hash", "iconv", "json",
               "libxml", "mbstring", "mysqlnd", "openssl", "pcre", "pdo", "pdo_sqlite", "phar", "posix",
               "readline", "reflection", "session", "simplexml", "sodium", "spl", "sqlite3", "standard",
               "tokenizer", "xml", "xmlreader", "xmlwriter", "zlib", "random"}
# Windows-only extensions (finding php-windows-extensions): no Linux build to install
PHP_WINDOWS_EXT = {"com_dotnet", "win32service", "win32ps", "wincache", "printer"}
PHP_FRAMEWORK_EXT = {
    "laravel": ["bcmath", "intl", "pdo_mysql", "pdo_pgsql", "zip"],
    "symfony": ["intl", "pdo_mysql", "pdo_pgsql", "zip"],
    "wordpress": ["exif", "gd", "intl", "mysqli", "zip"],
    "drupal": ["gd", "pdo_mysql", "pdo_pgsql", "zip"],
    "cakephp": ["intl", "pdo_mysql", "pdo_pgsql"],
    "codeigniter": ["intl", "mysqli", "pdo_mysql"],
    "yii": ["intl", "pdo_mysql", "pdo_pgsql"],
}
# extension -> what in the code says the app uses it (plain PHP sites declare nothing)
PHP_CODE_EXT = [
    ("mysqli", r"\bmysqli_\w+\s*\(|\bnew\s+mysqli\b"),
    ("pdo_mysql", r"['\"]mysql:(host|dbname|unix_socket)"),
    ("pdo_pgsql", r"['\"]pgsql:(host|dbname)"),
    ("pgsql", r"\bpg_(connect|pconnect|query)\s*\("),
    ("pdo_sqlsrv", r"['\"]sqlsrv:Server"),
    ("sqlsrv", r"\bsqlsrv_connect\s*\("),
    ("gd", r"\bimagecreate(truecolor|fromjpeg|frompng|fromgif)?\s*\("),
    ("ldap", r"\bldap_(connect|bind)\s*\("),
    ("soap", r"\bnew\s+\\?Soap(Client|Server)\b"),
    ("intl", r"\bnew\s+\\?(NumberFormatter|IntlDateFormatter|Collator)\b"),
    ("zip", r"\bnew\s+\\?ZipArchive\b"),
    ("gettext", r"\b(bindtextdomain|textdomain)\s*\("),
    ("bcmath", r"\bbc(add|sub|mul|div|mod|pow|comp)\s*\("),
    ("exif", r"\bexif_read_data\s*\("),
    ("xsl", r"\bnew\s+\\?XSLTProcessor\b"),
]

# native gems: (build packages, runtime packages) on Debian
RUBY_NATIVE = {
    "pg": (["libpq-dev"], ["libpq5"]),
    "mysql2": (["default-libmysqlclient-dev"], ["libmariadb3"]),
    "sqlite3": (["libsqlite3-dev"], ["libsqlite3-0"]),
    "tiny_tds": (["freetds-dev"], ["freetds-bin"]),
    "nokogiri": (["libxml2-dev", "libxslt1-dev", "zlib1g-dev"], ["libxml2", "libxslt1.1"]),
    "rmagick": (["libmagickwand-dev"], ["imagemagick"]),
    "mini_magick": ([], ["imagemagick"]),
    "ruby-vips": ([], ["libvips42"]),
    "image_processing": ([], ["libvips42"]),
    "psych": (["libyaml-dev"], ["libyaml-0-2"]),
    "ffi": (["libffi-dev"], ["libffi8"]),
    "grpc": ([], []),
    "wkhtmltopdf-binary": ([], ["libxrender1", "libfontconfig1", "libxext6"]),
}
RUBY_WORKERS = [   # gem -> how its worker process starts
    ("sidekiq", ["bundle", "exec", "sidekiq"]),
    ("good_job", ["bundle", "exec", "good_job", "start"]),
    ("shoryuken", ["bundle", "exec", "shoryuken", "-R"]),
    ("resque", ["bundle", "exec", "rake", "resque:work"]),
    ("delayed_job", ["bundle", "exec", "rake", "jobs:work"]),
    ("sneakers", ["bundle", "exec", "rake", "sneakers:run"]),
    ("que", ["bundle", "exec", "que"]),
    ("racecar", ["bundle", "exec", "racecar"]),
    ("karafka", ["bundle", "exec", "karafka", "server"]),
]
ENV_SECRET = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?|MASTER_KEY|"
                        r"APP_KEY|SECRET_KEY_BASE|(DATABASE|DB|MONGO(DB)?|REDIS|POSTGRES|MYSQL|AMQP|RABBITMQ)_(URL|URI|DSN)|DSN)$")


def _images() -> dict:
    from .generate import images
    return images()


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:2]) or (0,)


def _dotenv_secrets(p) -> list[str]:
    out = set()
    for n in (".env.example", ".env.sample", ".env.dist", ".env.template", "example.env", ".env"):
        f = p.dir / n
        if f.is_file():
            for line in f.read_text(errors="replace").splitlines():
                m = re.match(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", line)
                if m and ENV_SECRET.search(m.group(1)):
                    out.add(m.group(1))
    return sorted(out)


def _code(p, pattern: str, exts: tuple) -> list[tuple[str, str]]:
    """(file relative to the project, first match) of a pattern in the project's own source."""
    rx = re.compile(pattern)
    skip = re.compile(r"(^|/)(vendor|node_modules|tests?|spec)/")
    out = []
    for f in p.files:
        if f.suffix.lower() not in exts:
            continue
        rel = str(f.relative_to(p.dir)).replace("\\", "/")
        if skip.search(rel):
            continue
        m = rx.search(p.text(f))
        if m:
            out.append((rel, m.group(0)))
    return out


# --------------------------------------------------------------------------- facts

def php_ruby_facts(repo, c, facts: dict) -> None:
    p = c.project
    props = p.properties or {}
    fw = props.get("Framework", "")
    secrets = set(facts.get("secret_settings") or []) | set(_dotenv_secrets(p))
    if p.kind_hint == "php":
        if fw == "laravel":
            secrets |= {"APP_KEY", "DB_PASSWORD"}
        elif fw == "symfony":
            secrets |= {"APP_SECRET", "DATABASE_URL"}
        elif fw == "wordpress" and not (p.dir / "wp-config.php").is_file():
            secrets |= {"WORDPRESS_DB_PASSWORD"}
        uploads = set()
        for _, m in _code(p, r"move_uploaded_file\s*\([^,;]+,\s*(?:(?:__DIR__|dirname\(__FILE__\))\s*\.\s*)?['\"]\.?/?([\w\-]+)/",
                          (".php", ".phtml", ".inc")):
            uploads.add(re.search(r"['\"]\.?/?([\w\-]+)/$", m).group(1))
        if any(f.rule.id == "php-local-uploads" for f in c.findings) and not uploads:
            uploads |= {d for d in ("uploads", "upload", "files", "media") if (p.dir / d).is_dir()}
        if uploads:
            facts["upload_dirs"] = sorted(uploads)
        exts = set()
        for ext, rx in PHP_CODE_EXT:
            if _code(p, rx, (".php", ".phtml", ".inc", ".module")):
                exts.add(ext)
        if exts:
            facts["php_code_extensions"] = sorted(exts)
    else:
        if fw == "rails":
            secrets |= {"SECRET_KEY_BASE", "RAILS_MASTER_KEY", "DATABASE_URL"}
        if c.role == "worker" and fw not in ("rails",):
            files = _code(p, r"\binclude\s+Sidekiq::(Job|Worker)\b", (".rb",))
            if files:
                facts["sidekiq_require"] = "./" + sorted(files)[0][0]
    if secrets:
        facts["secret_settings"] = sorted(secrets)


# --------------------------------------------------------------------------- PHP plan

def php_line(props: dict, legacy_code: bool = False) -> str:
    im = _images()["php"]
    lines = list(im.get("lines") or [])
    legacy = dict(im.get("legacy") or {})
    if legacy_code:
        return "5.6"
    lo, hi = props.get("PhpVersion"), props.get("PhpVersionMax")
    wp = props.get("WordPressVersion")
    if wp and not hi and _ver(wp) < (5, 6):
        hi = "7.4"                                # WordPress before 5.6 does not run on PHP 8
    cands = sorted(set(lines) | set(legacy), key=_ver)

    def ok(v):
        if lo and _ver(v) < _ver(lo)[:2]:
            return False
        if hi:
            h = _ver(hi)
            return _ver(v)[:len(h)] <= h
        return True
    allowed = [v for v in cands if ok(v)]
    if allowed:
        return allowed[-1]
    return lines[-1] if not hi else cands[0] if _ver(hi) < _ver(cands[0]) else lines[-1]


def php_plan(a, c, plan: dict) -> None:
    from .generate import add_reason
    p, f = c.project, c.facts
    props = p.properties or {}
    fw = props.get("Framework", "plain")
    ids = {x.rule.id for x in c.findings}
    line = php_line(props, "php-removed-functions" in ids)
    im = _images()["php"]
    base = im.get(f"apache_{line.replace('.', '_')}") or (im.get("legacy") or {}).get(line)
    if line not in (im.get("lines") or []):
        add_reason(plan, "php-own-line", f"Runs on PHP {line}, the line the application allows (or needs), on its "
                   "last official image, which no longer gets security fixes.", ["https://www.php.net/supported-versions.php"])
    exts = set(e for e in (props.get("PhpExtensions") or "").split(",") if e)
    exts |= set(PHP_FRAMEWORK_EXT.get(fw, [])) | set(f.get("php_code_extensions") or [])
    if "php-removed-functions" in ids:
        exts.add("mysql")
    exts.add("opcache")
    skipped = sorted(exts & PHP_WINDOWS_EXT)
    exts = sorted(exts - PHP_BUILTIN - PHP_WINDOWS_EXT)
    if skipped:
        add_reason(plan, "php-windows-extensions", f"Windows-only extensions are left out ({', '.join(skipped)}): "
                   "PHP for Linux has no build of them.")
    docroot = props.get("DocRoot") or ""
    front = fw in ("laravel", "symfony", "wordpress", "drupal", "slim", "cakephp", "codeigniter", "yii") \
        or "php-iis-web-config" in ids
    writable: list[str] = []
    persistent: list[str] = []
    env = plan["env"]
    keep_dotenv = False
    if fw == "laravel":
        env.update({"APP_ENV": "production", "APP_DEBUG": "false", "LOG_CHANNEL": "stderr"})
        writable += [f"{PHP_ROOT}/storage/framework/cache", f"{PHP_ROOT}/storage/framework/sessions",
                     f"{PHP_ROOT}/storage/framework/views", f"{PHP_ROOT}/storage/logs", f"{PHP_ROOT}/bootstrap/cache",
                     f"{PHP_ROOT}/storage/app"]
        persistent.append(f"{PHP_ROOT}/storage/app")
        add_reason(plan, "php-laravel-env", "Laravel reads environment variables before .env: APP_ENV, APP_DEBUG and "
                   "LOG_CHANNEL=stderr (logs to the pod's output) are set in the image, credentials (APP_KEY, DB_*) "
                   "come from the Secret.", ["https://laravel.com/docs/configuration#environment-configuration"])
    elif fw == "symfony":
        env.update({"APP_ENV": "prod", "APP_DEBUG": "0"})
        plan["build_env"] = {"APP_ENV": "prod"}
        writable += [f"{PHP_ROOT}/var/cache", f"{PHP_ROOT}/var/log"]
        keep_dotenv = True
        add_reason(plan, "php-symfony-env", "Symfony loads the committed .env defaults (kept in the build context) "
                   "and real environment variables win over them: APP_ENV=prod is set, APP_SECRET and DATABASE_URL "
                   "come from the Secret.", ["https://symfony.com/doc/current/configuration.html#configuration-based-on-environment-variables"])
    elif fw == "wordpress":
        site = f"{PHP_ROOT}/{docroot}".rstrip("/")
        writable.append(f"{site}/wp-content/uploads")
        persistent.append(f"{site}/wp-content/uploads")
        if not (p.dir / docroot / "wp-config.php").is_file() and not (p.dir / "wp-config.php").is_file():
            plan["wp_config"] = f"{site}/wp-config.php"
            add_reason(plan, "php-wordpress-config", "The repository has no wp-config.php (it is kept out of source "
                       "control): the image gets one that reads WORDPRESS_DB_* and the salts from the environment, "
                       "as the official WordPress image does; the password comes from the Secret.",
                       ["https://github.com/docker-library/wordpress/blob/master/wp-config-docker.php"])
    elif fw == "drupal":
        site = f"{PHP_ROOT}/{docroot}".rstrip("/")
        writable.append(f"{site}/sites/default/files")
        persistent.append(f"{site}/sites/default/files")
    for d in f.get("upload_dirs") or []:
        w = f"{PHP_ROOT}/{d}"
        writable.append(w)
        persistent.append(w)
    # Apache started without root keeps its pid and lock files here
    writable += ["/var/run/apache2", "/var/lock/apache2"]
    for w in writable:
        if w not in plan["add_writable"]:
            plan["add_writable"].append(w)
    if persistent:
        plan["persistent"] = persistent
        plan["single_replica"] = True
    plan.update({"php": line, "php_base": base, "php_extensions": exts, "framework": fw, "docroot": docroot,
                 "front_controller": front, "composer": p.path.name == "composer.json",
                 "composer_lock": bool(props.get("Lockfile")), "uid": im["app_uid"], "base": "apache",
                 "app_dir": "" if p.rel_dir == "." else p.rel_dir.replace("\\", "/"), "keep_dotenv": keep_dotenv})
    plan["port"] = 8080
    if plan["composer"] and not plan["composer_lock"]:
        add_reason(plan, "php-no-lockfile", "There is no composer.lock: dependency versions are resolved at build "
                   "time and can change between builds. Commit composer.lock.",
                   ["https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control"])
    if front:
        add_reason(plan, "php-front-controller", "Requests that are not an existing file go to index.php "
                   "(FallbackResource), as the framework's .htaccess or IIS rewrite rules do.",
                   ["https://httpd.apache.org/docs/2.4/mod/mod_dir.html#fallbackresource"])


WP_CONFIG = r"""<?php
// Generated by containerizer: settings from the environment, as in the official WordPress image
// (wp-config-docker.php). Empty salts make WordPress keep generated ones in the database.
function containerizer_env($name, $default) { $v = getenv($name); return $v === false ? $default : $v; }
define('DB_NAME', containerizer_env('WORDPRESS_DB_NAME', 'wordpress'));
define('DB_USER', containerizer_env('WORDPRESS_DB_USER', 'wordpress'));
define('DB_PASSWORD', containerizer_env('WORDPRESS_DB_PASSWORD', ''));
define('DB_HOST', containerizer_env('WORDPRESS_DB_HOST', 'mysql'));
define('DB_CHARSET', containerizer_env('WORDPRESS_DB_CHARSET', 'utf8mb4'));
define('DB_COLLATE', containerizer_env('WORDPRESS_DB_COLLATE', ''));
foreach (array('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT') as $k) {
    define($k, containerizer_env('WORDPRESS_' . $k, ''));
}
$table_prefix = containerizer_env('WORDPRESS_TABLE_PREFIX', 'wp_');
define('WP_DEBUG', (bool) containerizer_env('WORDPRESS_DEBUG', ''));
// the image is read-only: plugins, themes and updates are installed by building a new image
define('DISALLOW_FILE_MODS', true);
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strpos($_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') !== false) {
    $_SERVER['HTTPS'] = 'on';
}
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}
require_once ABSPATH . 'wp-settings.php';
"""


def dockerfile_php(plan: dict) -> str:
    from .generate import reason_comments, writable_dirs
    im = _images()["php"]
    uid = plan["uid"]
    src = (plan.get("app_dir") or "").strip("/")
    docroot = f"{PHP_ROOT}/{plan['docroot']}".rstrip("/")
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, PHP {plan['php']}, {plan['framework']})",
             *reason_comments(plan),
             f"FROM {plan['php_base']} AS base"]
    if plan["php_extensions"]:
        lines += [f"COPY --from={im['extension_installer']} /usr/bin/install-php-extensions /usr/local/bin/",
                  "RUN --mount=type=secret,id=ca,required=false \\",
                  "    if [ -f /run/secrets/ca ]; then cp /run/secrets/ca /usr/local/share/ca-certificates/build-ca.crt && update-ca-certificates; fi; \\",
                  "    install-php-extensions " + " ".join(plan["php_extensions"])]
    conf = ["ServerName localhost", "ServerTokens Prod", "ServerSignature Off",
            "# behind the cluster's ingress: the client address and scheme come from X-Forwarded-*",
            "RemoteIPHeader X-Forwarded-For", "SetEnvIf X-Forwarded-Proto https HTTPS=on"]
    if plan.get("front_controller"):
        conf += [f"<Directory {docroot}>", "    FallbackResource /index.php", "</Directory>"]
    lines += ["# Apache on 8080 (no root needed to bind), the web root, production php.ini",
              "RUN sed -ri 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \\",
              " && sed -ri 's!<VirtualHost \\*:80>!<VirtualHost *:8080>!' /etc/apache2/sites-available/000-default.conf \\"]
    if plan["docroot"]:
        lines.append(f" && sed -ri 's!DocumentRoot /var/www/html$!DocumentRoot {docroot}!' /etc/apache2/sites-available/000-default.conf \\")
    lines += [" && a2enmod rewrite headers expires remoteip setenvif \\",
              ' && cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \\',
              " && printf 'expose_php = Off\\n' > \"$PHP_INI_DIR/conf.d/zz-containerizer.ini\"",
              "COPY <<'EOF' /etc/apache2/conf-enabled/zz-containerizer.conf", *conf, "EOF", ""]
    lines += ["FROM base AS build", f"WORKDIR {PHP_ROOT}", f"COPY {src + '/' if src else '.'} ."]
    if plan.get("composer"):
        benv = " ".join(f"{k}={json.dumps(str(v))}" for k, v in sorted((plan.get("build_env") or {}).items()))
        lines += [f"COPY --from={im['composer']} /usr/bin/composer /usr/bin/composer",
                  "RUN apt-get update && apt-get install -y --no-install-recommends git unzip && rm -rf /var/lib/apt/lists/*",
                  "ENV COMPOSER_ALLOW_SUPERUSER=1" + (f" {benv}" if benv else ""),
                  "# the post-install scripts (package discovery, cache warm-up) run when they can; they also run at start-up",
                  "RUN --mount=type=cache,target=/root/.composer/cache --mount=type=secret,id=ca,required=false \\",
                  f"    {CA_ENV}; \\",
                  "    composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader --no-progress \\",
                  "    || composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader --no-progress --no-scripts"]
    writable = [w for w in writable_dirs(plan) if w != "/tmp"]
    lines += ["", "FROM base AS final", f"WORKDIR {PHP_ROOT}",
              "# application files stay owned by root: read-only for the app user",
              f"COPY --from=build {PHP_ROOT} {PHP_ROOT}"]
    if plan.get("wp_config"):
        lines += [f"COPY <<'EOF' {plan['wp_config']}", WP_CONFIG.rstrip("\n"), "EOF"]
    if writable:
        lines.append("RUN mkdir -p " + " ".join(writable) + f" && chown -R {uid}:{uid} " + " ".join(writable))
    if plan["env"]:
        lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(plan["env"].items())))
    lines += [f"USER {uid}", "EXPOSE 8080", 'CMD ["apache2-foreground"]']
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Ruby plan

def ruby_image(props: dict) -> tuple[str, str]:
    """(image, Ruby line) for the app's declared Ruby."""
    im = _images()["ruby"]
    lines = list(im.get("lines") or [])
    legacy = dict(im.get("legacy") or {})
    exact = props.get("RubyExact")
    if exact:
        return f"ruby:{exact}-slim", ".".join(exact.split(".")[:2])
    v = props.get("RubyVersion")
    if not v:
        return im[f"slim_{lines[-1].replace('.', '_')}"], lines[-1]
    if v in lines:
        return im[f"slim_{v.replace('.', '_')}"], v
    if v in legacy:
        return legacy[v], v
    if _ver(v) < _ver(sorted(legacy, key=_ver)[0]):
        old = sorted(legacy, key=_ver)[0]
        return legacy[old], old
    newer = [x for x in lines if _ver(x) >= _ver(v)]
    x = newer[0] if newer else lines[-1]
    return im[f"slim_{x.replace('.', '_')}"], x


def ruby_plan(a, c, plan: dict) -> None:
    from .generate import add_reason
    p, f = c.project, c.facts
    props = p.properties or {}
    fw = props.get("Framework", "")
    runtime = {g for g in p.packages if g not in p.dev_packages}
    image, line = ruby_image(props)
    im = _images()["ruby"]
    if line not in (im.get("lines") or []):
        add_reason(plan, "ruby-own-line", f"Runs on Ruby {props.get('RubyExact') or line} as the application declares "
                   "(Bundler and native gems are tied to it), on its official image, which may no longer get fixes.",
                   ["https://www.ruby-lang.org/en/downloads/branches/"])
    build_pkgs, run_pkgs = {"build-essential", "git", "pkg-config", "libyaml-dev"}, set()
    for g, (b, r) in RUBY_NATIVE.items():
        if g in runtime:
            build_pkgs |= set(b)
            run_pkgs |= set(r)
    if fw == "rails":
        run_pkgs.add("tzdata")
    env = plan["env"]
    env.update({"RACK_ENV": "production", "APP_ENV": "production", "HOME": "/tmp",
                "BUNDLE_DEPLOYMENT": "1" if props.get("Lockfile") else "0", "BUNDLE_WITHOUT": "development:test"})
    writable = [f"{RUBY_ROOT}/tmp"]
    persistent = []
    if fw == "rails":
        env.update({"RAILS_ENV": "production", "RAILS_LOG_TO_STDOUT": "1", "RAILS_SERVE_STATIC_FILES": "1"})
        writable.append(f"{RUBY_ROOT}/log")
        add_reason(plan, "ruby-rails-env", "Rails runs in production, logs to the pod's output and serves its "
                   "precompiled assets (RAILS_LOG_TO_STDOUT, RAILS_SERVE_STATIC_FILES); DATABASE_URL, "
                   "SECRET_KEY_BASE and RAILS_MASTER_KEY come from the Secret and win over config/database.yml "
                   "and the credentials file.", ["https://guides.rubyonrails.org/configuring.html#configuring-a-database"])
    ids = {x.rule.id for x in c.findings}
    if "ruby-activestorage-disk" in ids or "ruby-sqlite-production" in ids:
        persistent.append(f"{RUBY_ROOT}/storage")
    if "ruby-sqlite-production" in ids:
        persistent.append(f"{RUBY_ROOT}/db")
    if "ruby-file-uploads-local" in ids:
        persistent += [f"{RUBY_ROOT}/public/system", f"{RUBY_ROOT}/public/uploads"]
    writable += persistent
    for w in writable:
        if w not in plan["add_writable"]:
            plan["add_writable"].append(w)
    if persistent:
        plan["persistent"] = persistent
        plan["single_replica"] = True
    # how it starts
    cfg_puma = (p.dir / "config" / "puma.rb").is_file()
    if c.role == "worker":
        cmd = next((list(cmd) for g, cmd in RUBY_WORKERS if g in runtime), None) or ["bundle", "exec", "ruby", "main.rb"]
        if cmd[2] == "sidekiq" and f.get("sidekiq_require"):
            cmd += ["-r", f["sidekiq_require"]]
        if cmd[3:4] == ["resque:work"]:
            env.setdefault("QUEUE", "*")
        plan["port"] = None
    elif "puma" in runtime:
        cmd = ["bundle", "exec", "puma"] + (["-C", "config/puma.rb"] if cfg_puma else ["-b", "tcp://0.0.0.0:8080"])
    elif "unicorn" in runtime:
        cmd = ["bundle", "exec", "unicorn", "-l", "0.0.0.0:8080", "-E", "production"]
    elif "thin" in runtime:
        cmd = ["bundle", "exec", "thin", "start", "-a", "0.0.0.0", "-p", "8080"]
    elif fw == "rails":
        cmd = ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "8080"]
    else:
        cmd = ["bundle", "exec", "rackup", "-o", "0.0.0.0", "-p", "8080"]
    if c.role != "worker":
        env["PORT"] = "8080"
        plan["port"] = 8080
        if cmd[2] != "puma":
            add_reason(plan, "ruby-server", f"Puma is not in the bundle: the image starts the server the bundle has "
                       f"(`{' '.join(cmd[2:])}`), so the Gemfile is not changed.")
        if cfg_puma:
            add_reason(plan, "ruby-puma-config", "Puma starts with the app's config/puma.rb, which takes the port "
                       "from PORT (8080).", ["https://puma.io/puma/Puma/DSL.html#port-instance_method"])
    # a Rails app's job processor runs from the same image as a second Deployment
    if fw == "rails" and c.role == "web":
        w = next(((g, list(cmd)) for g, cmd in RUBY_WORKERS if g in runtime), None)
        if w:
            plan["processes"] = [{"name": w[0], "args": w[1]}]
            add_reason(plan, "ruby-job-process", f"{w[0]} processes the app's background jobs in a process of its own: "
                       f"the manifests run `{' '.join(w[1])}` from the same image as a second Deployment.")
    assets = fw == "rails" and bool(runtime & {"sprockets-rails", "propshaft", "webpacker", "shakapacker",
                                               "jsbundling-rails", "cssbundling-rails", "sprockets", "sass-rails",
                                               "tailwindcss-rails", "dartsass-rails"})
    node = assets and (p.dir / "package.json").is_file() and bool(runtime & {"webpacker", "shakapacker", "jsbundling-rails",
                                                                                "cssbundling-rails"})
    platforms = [x for x in (props.get("LockPlatforms") or "").split(",") if x]
    add_platform = bool(platforms) and not any(x == "ruby" or "linux" in x for x in platforms)
    if add_platform:
        add_reason(plan, "ruby-lock-platform", f"Gemfile.lock lists only {', '.join(platforms)}: the build adds the "
                   "Linux platform to its own copy of the lockfile (bundle lock --add-platform), the repository's file "
                   "is not changed.", ["https://bundler.io/man/bundle-lock.1.html"])
    if not props.get("Lockfile"):
        add_reason(plan, "ruby-no-lockfile", "There is no Gemfile.lock: gem versions are resolved at build time and can "
                   "change between builds. Commit Gemfile.lock.", ["https://bundler.io/guides/rationale.html"])
    bundler = props.get("BundlerVersion") or ""
    if bundler and not re.fullmatch(r"[2-9]\.\d+\.\d+", bundler):
        bundler = ""                              # Bundler 1.x does not run on current Rubies: the image's own
    plan.update({"ruby": line, "ruby_image": image, "framework": fw, "cmd": cmd, "uid": im["app_uid"],
                 "build_packages": sorted(build_pkgs), "runtime_packages": sorted(run_pkgs), "assets": assets,
                 "node_assets": node, "add_platform": add_platform, "bundler": bundler, "base": "slim",
                 "app_dir": "" if p.rel_dir == "." else p.rel_dir.replace("\\", "/")})


def dockerfile_ruby(plan: dict) -> str:
    from .generate import reason_comments, writable_dirs
    uid = plan["uid"]
    src = (plan.get("app_dir") or "").strip("/")
    image = plan["ruby_image"]
    apt = "apt-get update && apt-get install -y --no-install-recommends {} && rm -rf /var/lib/apt/lists/*"
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, Ruby {plan['ruby']}"
             + (f", {plan['framework']}" if plan.get("framework") else "") + ")",
             *reason_comments(plan),
             f"FROM {image} AS build",
             "RUN " + apt.format(" ".join(plan["build_packages"] + (["nodejs", "npm"] if plan.get("node_assets") else [])))]
    lines += [f"WORKDIR {RUBY_ROOT}",
              "ENV BUNDLE_PATH=/usr/local/bundle BUNDLE_WITHOUT=development:test BUNDLE_JOBS=4"
              + (" RAILS_ENV=production" if plan.get("framework") == "rails" else "") + " RACK_ENV=production",
              f"COPY {src + '/' if src else '.'} ."]
    steps = []
    if plan.get("bundler"):
        steps.append(f"gem install bundler -v {plan['bundler']} --no-document")
    if plan.get("add_platform"):
        steps.append("bundle lock --add-platform ruby x86_64-linux aarch64-linux")
    if plan["env"].get("BUNDLE_DEPLOYMENT") == "1":
        steps.append("bundle config set --local deployment true")
    steps += ["bundle install", "rm -rf /usr/local/bundle/cache /usr/local/bundle/ruby/*/cache"]
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies",
              "RUN --mount=type=secret,id=ca,required=false \\",
              "    if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca; fi; \\",
              "    " + " \\\n && ".join(steps)]
    if plan.get("assets"):
        pre = "npm install -g yarn && " if plan.get("node_assets") else ""
        lines += ["# assets are compiled at build time; the dummy secret only lets Rails boot for it",
                  f"RUN {pre}SECRET_KEY_BASE_DUMMY=1 SECRET_KEY_BASE=precompile-only bundle exec rails assets:precompile"]
    lines += ["", f"FROM {image} AS final"]
    if plan["runtime_packages"]:
        lines.append("RUN " + apt.format(" ".join(plan["runtime_packages"])))
    lines += [f"WORKDIR {RUBY_ROOT}", "# application files stay owned by root: read-only for the app user",
              "COPY --from=build /usr/local/bundle /usr/local/bundle",
              f"COPY --from=build {RUBY_ROOT} {RUBY_ROOT}"]
    writable = [w for w in writable_dirs(plan) if w != "/tmp"]
    if writable:
        lines.append("RUN mkdir -p " + " ".join(writable) + f" && chown -R {uid}:{uid} " + " ".join(writable))
    env = {**plan["env"], "BUNDLE_PATH": "/usr/local/bundle"}
    lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    lines.append("ENTRYPOINT " + json.dumps(plan["cmd"] + list(plan.get("args") or [])))
    return "\n".join(lines) + "\n"


def php_ruby_buildable(c) -> bool:
    return c.role in ("web", "worker") and not any(
        f.severity == "blocker" for f in c.findings)


def dockerignore_for(plan: dict, text: str) -> str:
    """bin/ is a .NET build folder but holds Symfony's console and Rails' binstubs; Symfony needs its .env."""
    text = text.replace("**/bin/\n", "").replace("**/obj/\n", "")
    if plan.get("keep_dotenv"):
        text = text.replace("**/.env\n", "")
    return text


def extra_processes(docs: list[dict], plan: dict, name: str) -> None:
    """A second Deployment per extra process (a Rails app's Sidekiq) from the same image, without ports or probes."""
    import copy
    from .generate import k8s_name
    dep = next((d for d in docs if d.get("kind") == "Deployment"), None)
    if dep is None:
        return
    for proc in plan.get("processes") or []:
        d = copy.deepcopy(dep)
        pname = k8s_name(f"{name}-{proc['name']}")
        d["metadata"]["name"] = pname
        labels = {**d["metadata"]["labels"], "app.kubernetes.io/component": proc["name"]}
        d["metadata"]["labels"] = labels
        d["spec"]["selector"] = {"matchLabels": labels}
        d["spec"]["template"]["metadata"]["labels"] = labels
        ct = d["spec"]["template"]["spec"]["containers"][0]
        ct["name"] = k8s_name(proc["name"])
        ct["command"] = proc["args"][:1]
        ct["args"] = proc["args"][1:]
        for k in ("ports", "readinessProbe", "livenessProbe", "startupProbe"):
            ct.pop(k, None)
        # shared volumes (claims) stay on the web pod: a ReadWriteOnce claim cannot be mounted twice
        vols = d["spec"]["template"]["spec"].get("volumes") or []
        pvc = {v["name"] for v in vols if "persistentVolumeClaim" in v}
        for v in vols:
            if v["name"] in pvc:
                v.pop("persistentVolumeClaim")
                v["emptyDir"] = {}
        docs.insert(docs.index(dep) + 1, d)
