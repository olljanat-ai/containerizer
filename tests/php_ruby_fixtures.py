"""Small PHP and Ruby applications in the shapes real repositories have (Laravel, WordPress, Rails, ...)."""
import json
from pathlib import Path

from tests.test_engine import write


def laravel(root: Path, extra_require: dict | None = None) -> None:
    write(root, "composer.json", json.dumps({
        "name": "acme/intranet", "type": "project",
        "require": {"php": "^8.1", "laravel/framework": "^10.10", "guzzlehttp/guzzle": "^7.2", "ext-gd": "*",
                    **(extra_require or {})},
        "require-dev": {"phpunit/phpunit": "^10.1", "fakerphp/faker": "^1.9.1"},
        "autoload": {"psr-4": {"App\\": "app/"}},
        "scripts": {"post-autoload-dump": ["@php artisan package:discover --ansi"]}}))
    write(root, "composer.lock", json.dumps({"packages": [
        {"name": "laravel/framework", "version": "v10.48.4", "require": {"php": "^8.1", "ext-mbstring": "*",
                                                                          "ext-openssl": "*"}},
        {"name": "guzzlehttp/guzzle", "version": "7.8.1", "require": {"ext-json": "*"}},
        {"name": "intervention/image", "version": "2.7.2", "require": {"ext-fileinfo": "*"}}],
        "packages-dev": [], "platform": {"php": "^8.1"}}))
    write(root, "artisan", "#!/usr/bin/env php\n<?php\nrequire __DIR__.'/vendor/autoload.php';\n")
    write(root, "public/index.php", "<?php\nrequire __DIR__.'/../vendor/autoload.php';\n$app = require_once __DIR__.'/../bootstrap/app.php';\n")
    write(root, "public/.htaccess", "RewriteEngine On\nRewriteRule ^ index.php [L]\n")
    write(root, "bootstrap/app.php", "<?php\n$app = new Illuminate\\Foundation\\Application(dirname(__DIR__));\n")
    write(root, "bootstrap/cache/.gitignore", "*\n!.gitignore\n")
    write(root, "storage/app/public/.gitignore", "*\n")
    write(root, "storage/framework/views/.gitignore", "*\n")
    write(root, "storage/logs/.gitignore", "*\n")
    write(root, "app/Http/Controllers/UploadController.php",
          "<?php\nnamespace App\\Http\\Controllers;\nclass UploadController {\n"
          "  public function store($request) { return $request->file('doc')->store('docs'); }\n}\n")
    write(root, ".env.example", "APP_NAME=Intranet\nAPP_ENV=local\nAPP_KEY=\nAPP_DEBUG=true\nLOG_CHANNEL=stack\n"
          "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=intranet\nDB_USERNAME=root\nDB_PASSWORD=\n"
          "REDIS_PASSWORD=null\nMAIL_PASSWORD=null\n")
    write(root, "tests/Feature/ExampleTest.php", "<?php\nclass ExampleTest {}\n")


def wordpress(root: Path, config: bool = False) -> None:
    write(root, "index.php", "<?php\ndefine('WP_USE_THEMES', true);\nrequire __DIR__ . '/wp-blog-header.php';\n")
    write(root, "wp-blog-header.php", "<?php\nrequire_once __DIR__ . '/wp-load.php';\n")
    write(root, "wp-load.php", "<?php\nrequire_once ABSPATH . 'wp-config.php';\n")
    write(root, "wp-config-sample.php", "<?php\ndefine( 'DB_NAME', 'database_name_here' );\n"
          "define( 'DB_PASSWORD', 'password_here' );\n$table_prefix = 'wp_';\n")
    if config:
        write(root, "wp-config.php", "<?php\ndefine( 'DB_NAME', 'intranet' );\ndefine( 'DB_USER', 'wp' );\n"
              "define( 'DB_PASSWORD', 'changeme' );\ndefine( 'DB_HOST', 'mysql01.corp.local' );\n"
              "$table_prefix = 'wp_';\nrequire_once ABSPATH . 'wp-settings.php';\n")
    write(root, "wp-includes/version.php", "<?php\n$wp_version = '6.4.3';\n$required_php_version = '7.0.0';\n")
    write(root, "wp-includes/functions.php", "<?php\nfunction wp_upload_dir() { return WP_CONTENT_DIR . '/uploads'; }\n"
          "function wp_mkdir_p($t) { return mkdir($t, 0777, true); }\n")
    write(root, "wp-admin/index.php", "<?php\nrequire_once __DIR__ . '/admin.php';\n")
    write(root, "wp-content/index.php", "<?php\n// Silence is golden.\n")
    write(root, "wp-content/themes/acme/functions.php", "<?php\nadd_action('init', function () {});\n")
    write(root, "web.config", """<?xml version="1.0" encoding="UTF-8"?>
<configuration><system.webServer><rewrite><rules>
<rule name="WordPress" patternSyntax="Wildcard"><match url="*"/>
<conditions><add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true"/></conditions>
<action type="Rewrite" url="index.php"/></rule></rules></rewrite></system.webServer></configuration>
""")


def rails(root: Path, gems: str = "", ruby: str = "3.2.2") -> None:
    write(root, "Gemfile", f"""source "https://rubygems.org"
ruby "{ruby}"
gem "rails", "~> 7.1.3"
gem "pg", "~> 1.1"
gem "puma", ">= 5.0"
gem "bootsnap", require: false
gem "image_processing", "~> 1.2"
{gems}
group :development, :test do
  gem "debug", platforms: %i[ mri windows ]
  gem "rspec-rails"
end

group :development do
  gem "web-console"
end
""")
    write(root, "Gemfile.lock", """GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.3.2)
      rack (>= 2.2.4)
    bootsnap (1.18.3)
    debug (1.9.1)
    image_processing (1.12.2)
      ruby-vips (>= 2.0.17, < 3)
    pg (1.5.6)
    puma (6.4.2)
      nio4r (~> 2.0)
    rack (3.0.10)
    rails (7.1.3.2)
      actionpack (= 7.1.3.2)
    rspec-rails (6.1.2)
    ruby-vips (2.2.1)
    web-console (4.2.1)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  pg (~> 1.1)
  puma (>= 5.0)
  rails (~> 7.1.3)

RUBY VERSION
   ruby 3.2.2p53

BUNDLED WITH
   2.5.6
""")
    write(root, "config.ru", 'require_relative "config/environment"\nrun Rails.application\n')
    write(root, "config/application.rb", "require 'rails/all'\nmodule Shop\n  class Application < Rails::Application\n"
          "    config.load_defaults 7.1\n  end\nend\n")
    write(root, "config/environment.rb", 'require_relative "application"\nRails.application.initialize!\n')
    write(root, "config/puma.rb", 'port ENV.fetch("PORT") { 3000 }\nworkers ENV.fetch("WEB_CONCURRENCY") { 0 }\n')
    write(root, "config/database.yml", "production:\n  adapter: postgresql\n  url: <%= ENV['DATABASE_URL'] %>\n")
    write(root, "config/storage.yml", "local:\n  service: Disk\n  root: <%= Rails.root.join(\"storage\") %>\n")
    write(root, "config/environments/production.rb",
          "Rails.application.configure do\n  config.active_storage.service = :local\nend\n")
    write(root, "app/controllers/application_controller.rb", "class ApplicationController < ActionController::Base\nend\n")
    write(root, "spec/models/order_spec.rb", "RSpec.describe Order do\nend\n")
    write(root, ".ruby-version", f"ruby-{ruby}\n")


def sinatra(root: Path) -> None:
    write(root, "Gemfile", 'source "https://rubygems.org"\ngem "sinatra"\ngem "puma"\n')
    write(root, "config.ru", 'require "./app"\nrun Sinatra::Application\n')
    write(root, "app.rb", 'require "sinatra"\nget("/") { "ok" }\n')


def sidekiq_worker(root: Path) -> None:
    write(root, "Gemfile", 'source "https://rubygems.org"\ngem "sidekiq", "~> 7.2"\ngem "redis"\n')
    write(root, "worker.rb", 'require "sidekiq"\nclass HardWorker\n  include Sidekiq::Job\n  def perform(id); end\nend\n')
