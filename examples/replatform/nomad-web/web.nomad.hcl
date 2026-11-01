# Nomad job
job "web" {
  datacenters = ["dc1"]
  type = "service"
  group "web" {
    count = 2
    network {
      port "http" { to = 3000 }
    }
    service {
      name = "web"
      port = "http"
      tags = ["traefik.enable=true", "traefik.http.routers.web.rule=Host(`web.example.com`)"]
      check {
        type     = "http"
        path     = "/api/health"
        interval = "10s"
        timeout  = "2s"
      }
    }
    task "web" {
      driver = "docker"
      config {
        image = "ghcr.io/acme/web:2.0"
        ports = ["http"]
      }
      env {
        NODE_ENV = "production"
        PORT     = "3000"
      }
      template {
        data = <<EOH
DATABASE_URL={{ with secret "kv/data/web" }}{{ .Data.data.url }}{{ end }}
API_BASE=https://api.example.com
EOH
        destination = "secrets/app.env"
        env         = true
      }
      resources {
        cpu    = 500
        memory = 256
      }
    }
  }
}
job "cleanup" {
  type = "batch"
  periodic { cron = "*/15 * * * *" }
  group "c" { task "c" { driver = "docker" config { image = "ghcr.io/acme/cleanup:1" args = ["--days", "7"] } } }
}
