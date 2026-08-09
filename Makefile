.PHONY: check typecheck test spec-guard

check:
	bun run check

typecheck:
	bun run typecheck

test:
	bun run test

spec-guard:
	bun run spec:guard
