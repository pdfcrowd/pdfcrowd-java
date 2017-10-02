.PHONY : all

all:
	mvn clean verify

publish:
	mvn install