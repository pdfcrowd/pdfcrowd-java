.PHONY : dist clean

DIR_NAME := pdfcrowd-4.2.0

compile:
	@mvn clean verify

clean:
	@rm -rf dist

dist:
	@mkdir -p dist
	@cd dist && mkdir -p $(DIR_NAME) && cp ../target/pdfcrowd*.jar $(DIR_NAME) && zip pdfcrowd.zip $(DIR_NAME)/*

publish: clean compile dist
	@mvn install
	@mvn deploy
	@echo To publish staging repository use Close on https://oss.sonatype.org/#stagingRepositories
