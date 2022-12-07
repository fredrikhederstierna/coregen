
# Simple LaTeX document generator skeleton.
# Fredrik Hederstierna 2022

SRC_TEX    = main
OUT_PATH   = out
BUILD_PATH = build
DST_PDF    = gump_spec
FLAGS      = -silent

all: $(DST_PDF).pdf makefile
	@echo Document $(OUT_PATH)/$(DST_PDF).pdf generated.

$(DST_PDF).pdf:
	@echo Generating $(DST_PDF)...
	latexmk $(FLAGS) -pdf -pdflatex="pdflatex -interaction=nonstopmode" -use-make -outdir=$(BUILD_PATH) $(SRC_TEX).tex
	@echo Copy generated doc to out dir
	@mkdir -p $(OUT_PATH)
	@cp $(BUILD_PATH)/$(SRC_TEX).pdf $(OUT_PATH)/$@

install_pkg:
#       # Install TexLive base
	sudo apt-get -y install texlive-latex-base
	sudo apt-get -y install latexmk
#       # Install some recommended and extra fonts
	sudo apt-get -y install texlive-latex-recommended
	sudo apt-get -y install texlive-fonts-recommended
	sudo apt-get -y install texlive-fonts-extra
#       # Install some extra packages
	sudo apt-get -y install texlive-latex-extra
	sudo apt-get -y install texlive-pictures
#       # Install everything (last resort if nothing else works)
#	# sudo apt-get -y install texlive-full

clean:
#	rm -f *.aux *.log *.pdf *.out *.toc
#	rm -f $(OUT_PATH)/$(DST_PDF).pdf
	rm -fr $(BUILD_PATH)
	rm -fr $(OUT_PATH)

.PHONY: clean all
