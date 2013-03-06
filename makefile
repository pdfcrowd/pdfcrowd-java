VERSION = 2.4
JAR = pdfcrowd.jar
ZIPSTEM = pdfcrowd-$(VERSION)-java
ZIPFILE = dist/$(ZIPSTEM).zip

-include .config
ifeq ($(JAVA_HOME),)
	JAVA_HOME := /usr/bin/
endif

JAVAC := $(JAVA_HOME)/javac
JAVA := $(JAVA_HOME)/java

all: $(JAR)
dist: $(ZIPFILE)

$(ZIPFILE) : $(JAR)
	mkdir -p dist
	rm -rf $(ZIPSTEM) && mkdir -p $(ZIPSTEM)
	cp -r --parents $(JAR) com/pdfcrowd/*.java FILES.txt $(ZIPSTEM)
	zip -r $(ZIPFILE) $(ZIPSTEM)
	rm -rf $(ZIPSTEM)

$(JAR) : com/pdfcrowd/Client.class com/pdfcrowd/PdfcrowdError.class
	$(JAVA_HOME)/jar cvf $(JAR) com/pdfcrowd/*.class

dist-check:
	@rm -rf /tmp/jpdfcrowd/
	@mkdir /tmp/jpdfcrowd/
	@unzip -d /tmp/jpdfcrowd/ $(JAR) > /dev/null
	@grep 'Created-By: 1.5' /tmp/jpdfcrowd/META-INF/MANIFEST.MF || (echo "pdfcrowd.jar is not version 1.5"; false)

com/pdfcrowd/Client.class: com/pdfcrowd/Client.java
	$(JAVAC) com/pdfcrowd/Client.java

com/pdfcrowd/PdfcrowdError.class: com/pdfcrowd/PdfcrowdError.java
	$(JAVAC) com/pdfcrowd/PdfcrowdError.java

test: $(JAR)
	$(JAVAC) -classpath . apitest.java
	$(JAVA) -classpath . apitest $(API_USERNAME) $(API_TOKEN) $(API_HOSTNAME) $(API_HTTP_PORT) $(API_HTTPS_PORT)


.PHONY: clean
clean:
	rm -rf $(ZIPFILE) dist/* ./test_files/out/java_*.pdf
	find . -name '*.class' -delete
