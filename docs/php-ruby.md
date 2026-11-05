# PHP and Ruby

PHP sites (Laravel, Symfony, WordPress, Drupal, Slim, CakePHP, CodeIgniter, Yii, and plain PHP with
or without Composer) and Ruby applications (Rails, Sinatra, Hanami, Roda, plain Rack, and job
processors such as Sidekiq) are assessed and containerized like the other stacks: rules first, every
finding explained, the same ratings, the same stateless requirement for an **A**. Nothing from the
repository is built or run during the assessment, and **no file of the application is changed**:
everything that differs from how the app ran before is in the image, the environment or the
manifests.

## What is read

**PHP** (`containerizer/scan_php_ruby.py`)

- `composer.json`: `require` / `require-dev` (dev packages kept apart), the PHP constraint
  (`require.php`, or `config.platform.php`), the `ext-*` extensions, `type` (library, plugin,
  project) and `bin`. The framework comes from its package (`laravel/framework`,
  `symfony/framework-bundle`, `drupal/core`, `roots/wordpress`, ...).
- `composer.lock`: the locked versions, the `ext-*` that locked packages need, and the PHP versions
  they support: a locked package that stops at PHP 8.2 caps the PHP line, since `composer install`
  refuses a PHP the lockfile was not resolved for.
- Sites without Composer: the shallowest folder with an `index.php` that no other project contains
  (WordPress core is one site, not one per `wp-admin/index.php`). WordPress is recognised by
  `wp-includes/` or `wp-config(-sample).php`, its version from `wp-includes/version.php`.
- The web root: `public/`, `web/`, `webroot/`, `htdocs/`, `public_html/` or `www/` when it holds
  `index.php`, else the folder itself.
- `vendor/`, `node_modules/` and `tests/` are not searched by code rules, and Composer packages
  under `vendor/` or `wp-content/` are not projects.

**Ruby**

- `Gemfile`: gems, with those only in `development` / `test` groups kept apart; `ruby "x.y.z"`
  (also `ruby file: ".ruby-version"`), `gemspec`.
- `Gemfile.lock`: locked versions, `RUBY VERSION`, `BUNDLED WITH` and `PLATFORMS`.
- `.ruby-version`, `.tool-versions`, `config.ru`, `config/application.rb`.
- `vendor/`, `spec/`, `test/` and `features/` are not searched by code rules.

## Roles

| Role | PHP | Ruby |
| --- | --- | --- |
| web | a front controller (`index.php` in the folder or its web root) or a web framework | Rails, or a Rack app (`config.ru`) |
| worker | | Sidekiq, Resque, GoodJob, Shoryuken, Sneakers, Delayed Job, Que, Racecar, Karafka without a web front |
| library | Composer `type` library, WordPress/Drupal plugin or theme, Symfony bundle | a gem (`.gemspec`) |
| tool | a Composer package with `bin` and no front controller | Jekyll, Middleman, fastlane, CocoaPods, Danger, linters |

A Rails app with Sidekiq (or another job gem) is one web component: its job process runs from the
same image as a second Deployment (`<component>-sidekiq`, `bundle exec sidekiq`).

## Findings

Rules are in `rules/15-php-ruby.yaml`.

| Rule | Severity | What |
| --- | --- | --- |
| `php-windows-extensions` | rewrite | `com_dotnet` (`new COM`, `new DOTNET`), `win32service`, WinCache, printer |
| `php-removed-functions` | config | `mysql_*` / `ereg*`: the app runs on PHP 5.6 as it is |
| `php-eol-version` | config | composer.json allows no supported PHP line (8.2+) |
| `php-iis-web-config` | info | IIS URL Rewrite rules in `web.config`; the image routes to `index.php` |
| `php-wordpress-uploads`, `php-drupal-files`, `php-laravel-local-disk`, `php-local-uploads` | config, state | files on the app's own disk: a PersistentVolumeClaim, one replica |
| `ruby-windows-gems` | rewrite | WIN32OLE, win32-service, the registry and Windows API gems |
| `ruby-eol-version` | config | a Ruby line without security fixes (3.2 and older) |
| `ruby-activestorage-disk`, `ruby-file-uploads-local`, `ruby-sqlite-production` | config, state | files or SQLite on the app's own disk |

Out-of-support runtimes are not a code change: the app runs on the line it was written for (its last
official image), and the platform hardening (non-root, read-only root file system, no capabilities,
network policies) contains it.

## Containers

The base images are in `rules/images.yaml` (`php`, `ruby`); `containerizer images --update` locks
them like the others.

**PHP**: the official `php:<line>-apache` image, the newest line the constraints allow (8.2 to 8.4,
older lines on their last image; 5.6 for code that needs `mysql_*`). Apache with mod_php keeps the
app's `.htaccess` rules working.

- Extensions: the `ext-*` of the app and its lockfile, the framework's usual ones (Laravel: bcmath,
  intl, pdo_mysql, pdo_pgsql, zip; WordPress: mysqli, gd, exif, intl, zip; ...), and those the code
  shows it uses (`mysqli_*`, `pgsql:` DSNs, `sqlsrv`, `ldap_*`, `SoapClient`, ...), installed with
  `install-php-extensions`. Extensions compiled into the image and Windows-only ones are left out.
- Apache listens on 8080 and runs as `www-data` (33) without root; the web root is set to the
  app's (`public/`), `ServerTokens Prod`, `expose_php = Off`, the production `php.ini`,
  `X-Forwarded-For`/`-Proto` from the ingress. Frameworks with a front controller (and sites with
  IIS rewrite rules) get `FallbackResource /index.php`.
- Composer installs `--no-dev` in a build stage; the final image has the app owned by root, so it is
  read-only to the app user. Writable: `/tmp`, Apache's run and lock folders, and what the app
  writes (Laravel `storage/` and `bootstrap/cache`, Symfony `var/`, WordPress `wp-content/uploads`,
  Drupal `sites/default/files`, upload folders). Folders with data are PersistentVolumeClaims.
- Configuration by environment, where the framework reads it: Laravel `APP_ENV=production`,
  `APP_DEBUG=false`, `LOG_CHANNEL=stderr`, with `APP_KEY` and `DB_*` credentials from the Secret
  (Laravel reads variables over `.env`, which stays out of the image); Symfony `APP_ENV=prod` with
  `APP_SECRET` and `DATABASE_URL` from the Secret (its committed `.env` defaults stay in the build
  context). A WordPress repository without `wp-config.php` (it is usually kept out of source
  control) gets one in the image that reads `WORDPRESS_DB_*` and the salts from the environment, as
  the official WordPress image does, with `DISALLOW_FILE_MODS` (plugins and updates come with a new
  image). A repository's own `wp-config.php` is used as it is.

**Ruby**: the slim image of the Ruby the app declares. An exact `ruby "3.2.2"` in the Gemfile gets
`ruby:3.2.2-slim`, because Bundler refuses any other version; otherwise the declared line, or the
newest supported one (3.3, 3.4).

- A build stage with a compiler and the `-dev` packages of the native gems in the bundle (`pg`,
  `mysql2`, `sqlite3`, `tiny_tds`, `nokogiri`, `rmagick`, ...) runs `bundle install` without the
  development and test groups, as a deployment (frozen) bundle when there is a lockfile, with the
  Bundler version of `BUNDLED WITH`. A lockfile made on Windows or macOS only gets the Linux platform
  in the build's own copy (`bundle lock --add-platform`).
- Rails assets are precompiled at build time with a dummy secret (Node.js is added for
  jsbundling/cssbundling and Webpacker).
- The final image adds only the runtime libraries (`libpq5`, `libvips42`, `tzdata`, ...) and runs as
  uid 65532 with `/tmp`, `tmp/` and `log/` writable (and `storage/`, `db/`, `public/system` when a
  state finding says the app keeps data there, as PersistentVolumeClaims).
- Start: Puma (`-C config/puma.rb` when the app has one: it reads `PORT`), else the server in the
  bundle (Unicorn, Thin, `rails server`, `rackup`), so the Gemfile is not changed. Workers start
  their job processor (`bundle exec sidekiq -r ./worker.rb` outside Rails).
- Rails: `RAILS_ENV=production`, `RAILS_LOG_TO_STDOUT`, `RAILS_SERVE_STATIC_FILES`, with
  `DATABASE_URL`, `SECRET_KEY_BASE` and `RAILS_MASTER_KEY` from the Secret (they win over
  `config/database.yml` and the credentials file).

Credentials named in `.env.example` (and the framework's own: `APP_KEY`, `SECRET_KEY_BASE`, ...) are
Secret references in the manifests, filled by External Secrets.
