.DEFAULT_GOAL := help

clean: ## Clean Haskell local packages
	@stack clean

install: ## Compile
	@stack install

repl: ## Launch ghci
	@stack ghci match

spec: ## Run the specs
	@stack test --fast --file-watch

watch: ## Compile on file changes
	@stack install --fast --file-watch

help: ## Print available tasks
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY:
	clean
	install
	repl
	spec
	watch
	help
