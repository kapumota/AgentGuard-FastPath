# Makefile de AgentGuard-C
# Software para investigación en DevSecOps de agentes

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -I./include -D_GNU_SOURCE
LDFLAGS = -lssl -lcrypto

SRCDIR  = src
INCDIR  = include
OBJDIR  = obj
BINDIR  = bin

SOURCES = $(SRCDIR)/audit.c $(SRCDIR)/config.c $(SRCDIR)/integrity.c $(SRCDIR)/main.c $(SRCDIR)/monitor.c $(SRCDIR)/sandbox.c $(SRCDIR)/utils.c
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
TARGET  = $(BINDIR)/agentguard
FASTPATH_TARGET = $(BINDIR)/agfast
FASTPATH_SOURCE = $(SRCDIR)/fastpath.c
FASTPATH_MODULES = $(SRCDIR)/common.c $(SRCDIR)/string_list.c
FASTPATH_LDFLAGS = -lm
BENCH_DIR ?= /tmp/agfast_bench
ROOT_REPORTS = report.json report.html alerts.csv stats.json graph.json timeline.json similarity.json
ROOT_REPORTS += agfast-report.json agfast-report.html agfast-alerts.csv
ROOT_REPORTS += agfast-stats.json agfast-graph.json agfast-timeline.json agfast-similarity.json

.PHONY: all clean clean-reports install test test-fastpath test-algorithms test-reports test-regression test-valgrind benchmark benchmark-csv

all: dirs $(TARGET) $(FASTPATH_TARGET)

dirs:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Compilado: $@"

$(FASTPATH_TARGET): $(FASTPATH_SOURCE) $(FASTPATH_MODULES)
	$(CC) $(CFLAGS) $(FASTPATH_SOURCE) $(FASTPATH_MODULES) -o $@ $(FASTPATH_LDFLAGS)
	@echo "Compilado: $@"

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/main.o: $(SRCDIR)/main.c $(INCDIR)/agentguard.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)
	rm -f $(ROOT_REPORTS)
	@echo "Artefactos de compilación y reportes locales eliminados"

clean-reports:
	rm -f $(ROOT_REPORTS)
	@echo "Reportes locales eliminados"

install: all
	install -D $(TARGET) /usr/local/bin/agentguard
	install -D -m 644 config/default.yml /etc/agentguard/default.yml
	@echo "Instalado en /usr/local/bin/agentguard"

test: all
	@echo "Ejecutando pruebas básicas..."
	$(BINDIR)/agentguard --version
	$(BINDIR)/agfast --version
	$(BINDIR)/agfast analyze examples/events.jsonl --policy examples/policy.json --risk --report /tmp/agfast-report.json --html /tmp/agfast-report.html --alerts-csv /tmp/agfast-alerts.csv || test $$? -eq 2
	$(BINDIR)/agfast stats examples/events_day2.jsonl --report /tmp/agfast-stats-dia2.json
	$(BINDIR)/agfast stats examples/events.csv --report /tmp/agfast-stats-csv.json
	$(BINDIR)/agfast graph examples/events_day3.jsonl --policy examples/policy.json --pid 123 --timeline --report /tmp/agfast-graph-dia3.json
	$(BINDIR)/agfast check-file /etc/passwd --policy examples/policy.json --report /tmp/agfast-check-file.json
	$(BINDIR)/agfast check-ip 45.90.10.2 --policy examples/policy.json --report /tmp/agfast-check-ip.json
	$(BINDIR)/agfast check-domain malicious.example --policy examples/policy.json --report /tmp/agfast-check-domain.json
	test -s /tmp/agfast-report.json
	test -s /tmp/agfast-stats-dia2.json
	test -s /tmp/agfast-stats-csv.json
	test -s /tmp/agfast-graph-dia3.json
	test -s /tmp/agfast-check-file.json
	python3 -m json.tool /tmp/agfast-report.json >/dev/null
	python3 -m json.tool /tmp/agfast-stats-csv.json >/dev/null
	python3 -m json.tool /tmp/agfast-check-file.json >/dev/null
	$(BINDIR)/agfast timeline examples/events_day3.jsonl --policy examples/policy.json --pid 123 --report /tmp/agfast-timeline-dia3.json
	$(BINDIR)/agfast generate --events 1000 --output /tmp/agfast-generated.jsonl --malicious-ratio 0.05
	$(BINDIR)/agfast stats /tmp/agfast-generated.jsonl --window-events 100 --report /tmp/agfast-generated-stats.json
	$(BINDIR)/agfast similarity examples/events_day3.jsonl --process python --compare-process bash --policy examples/policy.json --report /tmp/agfast-similarity.json
	$(BINDIR)/agfast tail examples/events.jsonl --policy examples/policy.json >/tmp/agfast-tail.txt
	$(BINDIR)/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test --report /tmp/agfast-check-cuckoo.json
	test -s /tmp/agfast-report.html
	test -s /tmp/agfast-alerts.csv
	test -s /tmp/agfast-timeline-dia3.json
	test -s /tmp/agfast-generated.jsonl
	python3 -m json.tool /tmp/agfast-timeline-dia3.json >/dev/null
	python3 -m json.tool /tmp/agfast-generated-stats.json >/dev/null
	python3 -m json.tool /tmp/agfast-similarity.json >/dev/null
	python3 -m json.tool /tmp/agfast-check-cuckoo.json >/dev/null
	grep -q "CRITICAL" /tmp/agfast-tail.txt
	@echo "Pruebas superadas"

debug: CFLAGS = -Wall -Wextra -O0 -g -I./include -D_GNU_SOURCE -DDEBUG
debug: all

release: CFLAGS = -Wall -Wextra -O3 -I./include -D_GNU_SOURCE -DNDEBUG
release: LDFLAGS = -lssl -lcrypto -s
release: all

benchmark: all
	@echo "Benchmark grande de AgentGuard FastPath"
	@mkdir -p $(BENCH_DIR)
	$(BINDIR)/agfast generate --events 10000 --output $(BENCH_DIR)/events_10000.jsonl --malicious-ratio 0.05
	$(BINDIR)/agfast generate --events 100000 --output $(BENCH_DIR)/events_100000.jsonl --malicious-ratio 0.05
	$(BINDIR)/agfast generate --events 1000000 --output $(BENCH_DIR)/events_1000000.jsonl --malicious-ratio 0.02
	@printf "| Eventos | Modo stats: tiempo y memoria |\n|---:|---|\n"
	@for n in 10000 100000 1000000; do \
	  $(BINDIR)/agfast stats $(BENCH_DIR)/events_$$n.jsonl --window-events 10000 --report $(BENCH_DIR)/stats_$$n.json >/tmp/agfast_bench_out.txt; \
	  line=$$(grep "Tiempo de análisis" /tmp/agfast_bench_out.txt | head -1 | sed 's/^ *//'); \
	  mem=$$(grep "Relación exacta" /tmp/agfast_bench_out.txt | head -1 | sed 's/^ *//'); \
	  printf "| $$n | $$line ; $$mem |\n"; \
	done
	@echo "Benchmark de alertas/riesgo con política en 10k eventos"
	@$(BINDIR)/agfast analyze $(BENCH_DIR)/events_10000.jsonl --policy examples/policy.json --risk --report $(BENCH_DIR)/report_10000.json --alerts-csv $(BENCH_DIR)/alerts_10000.csv >/tmp/agfast_analyze_10k.txt || test $$? -eq 2
	@grep -E "Eventos procesados|Alertas totales|Procesos de mayor riesgo|Reporte JSON|CSV de alertas" /tmp/agfast_analyze_10k.txt || true

benchmark-csv: all
	@echo "Benchmark CSV opcional con 100k eventos"
	@mkdir -p $(BENCH_DIR)
	$(BINDIR)/agfast generate --events 100000 --output $(BENCH_DIR)/events_100000.csv --format csv --malicious-ratio 0.05
	$(BINDIR)/agfast stats $(BENCH_DIR)/events_100000.csv --report $(BENCH_DIR)/stats_100000_csv.json | grep -E "Eventos procesados|Tiempo de análisis|Comparación|Exacta estimada|Probabilística fija|Relación exacta"
	@echo "Reporte CSV en $(BENCH_DIR)/stats_100000_csv.json"

test-algorithms: all
	@echo "Pruebas formales de algoritmos FastPath"
	$(BINDIR)/agfast stats examples/events_day2.jsonl --window-events 25 --report /tmp/agfast-algo-stats.json >/tmp/agfast-algo-stats.txt
	grep -q "Count-Min Sketch" /tmp/agfast-algo-stats.txt
	grep -q "HyperLogLog" /tmp/agfast-algo-stats.txt
	grep -q "Space-Saving" /tmp/agfast-algo-stats.txt
	$(BINDIR)/agfast check-ip 45.90.10.2 --policy examples/policy.json --delete-test --report /tmp/agfast-algo-cuckoo.json
	$(BINDIR)/agfast similarity examples/events_day3.jsonl --process python --compare-process bash --policy examples/policy.json --report /tmp/agfast-algo-similarity.json
	python3 -m json.tool /tmp/agfast-algo-stats.json >/dev/null
	python3 -m json.tool /tmp/agfast-algo-cuckoo.json >/dev/null
	python3 -m json.tool /tmp/agfast-algo-similarity.json >/dev/null
	@echo "Pruebas de algoritmos superadas"

test-reports: all
	@echo "Pruebas de reportes FastPath"
	$(BINDIR)/agfast analyze examples/events.jsonl --policy examples/policy.json --risk --window-events 3 --report /tmp/agfast-reports.json --html /tmp/agfast-reports.html --alerts-csv /tmp/agfast-reports.csv >/tmp/agfast-reports.txt || test $$? -eq 2
	test -s /tmp/agfast-reports.json
	test -s /tmp/agfast-reports.html
	test -s /tmp/agfast-reports.csv
	python3 -m json.tool /tmp/agfast-reports.json >/dev/null
	grep -q "AgentGuard FastPath" /tmp/agfast-reports.html
	grep -q "severity,pid,process" /tmp/agfast-reports.csv
	@echo "Pruebas de reportes superadas"


test-regression: all
	@echo "Pruebas de regresion FastPath"
	./tests/test_regression.sh

test-valgrind: all
	@if command -v valgrind >/dev/null 2>&1; then 	  echo "Prueba Valgrind de agfast"; 	  valgrind --leak-check=full --error-exitcode=1 $(BINDIR)/agfast analyze tests/fixtures/events_regression.jsonl --policy tests/fixtures/policy_regression.json --risk --report /tmp/agfast-valgrind.json >/tmp/agfast-valgrind.out || test $$? -eq 2; 	  python3 -m json.tool /tmp/agfast-valgrind.json >/dev/null; 	else 	  echo "Valgrind no esta instalado; prueba omitida"; 	fi

test-fastpath: test test-algorithms test-reports

.PHONY: test-streaming
test-streaming: all
	bash tests/test_streaming.sh

.PHONY: ebpf-check
ebpf-check:
	@bash ebpf/check_ebpf_env.sh

.PHONY: ebpf-info
ebpf-info:
	@echo "Soporte eBPF opcional"
	@echo "La compilacion normal de agfast no requiere eBPF"
	@echo "Ejecuta: make ebpf-check"

.PHONY: test-guardsketch
test-guardsketch:
	bash tests/test_guardsketch.sh

.PHONY: test-unit
test-unit:
	mkdir -p obj/unit
	$(CC) $(CFLAGS) -Ithird_party/unity tests/unit/test_probabilistic.c third_party/unity/unity.c -lm -o obj/unit/test_probabilistic
	$(CC) $(CFLAGS) -Ithird_party/unity tests/unit/test_graph_model.c third_party/unity/unity.c -o obj/unit/test_graph_model
	$(CC) $(CFLAGS) -Ithird_party/unity tests/unit/test_risk_helpers.c third_party/unity/unity.c -o obj/unit/test_risk_helpers
	./obj/unit/test_probabilistic
	./obj/unit/test_graph_model
	./obj/unit/test_risk_helpers
