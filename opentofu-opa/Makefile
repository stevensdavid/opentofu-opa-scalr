MOCK_DIRS := $(dir $(wildcard aws/controls/test_data/*/*/main.tofu))
MOCK_FILES := $(addsuffix mock.json,$(MOCK_DIRS))

debug:
	@echo $(MOCK_DIRS)
	@echo $(MOCK_FILES)

.PHONY: test
test: aws/controls/mocks.json
	opa test -v .

# In Makefile
aws/controls/mocks.json: $(MOCK_FILES) aws/controls/test_data/combine_mocks.sh
	./aws/controls/test_data/combine_mocks.sh $^ > $@

%/.terraform:
	cd $* && tofu init

%/pass.tfplan: %/.terraform %/main.tofu %/pass/main.tofu
	cd $* && tofu plan --exclude module.fail --out=pass.tfplan

%/fail.tfplan: %/.terraform %/main.tofu %/fail/main.tofu
	cd $* && tofu plan --exclude module.pass --out=fail.tfplan

%/mock.json: %/pass.json %/fail.json
	echo "{\"pass\":$$(cat $*/pass.json),\"fail\":$$(cat $*/fail.json)}" > $@ && \
	   rm $*/pass.json $*/fail.json # thse two files could cause conflicts otherwise



%.json: %.tfplan
	cd $$(dirname "$*") && tofu show -json $$(basename "$*").tfplan > $$(basename "$*").json
