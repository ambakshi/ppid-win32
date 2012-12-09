.PHONY: all clean

all: ppid.exe

OPT=/O2 /Os
CL=cl
LIBS=shell32.lib kernel32.lib user32.lib

%.exe: %.cpp
	$(CL) /nologo $^ $(OPT) /link /nologo $(LIBS) /out:$@

clean:
	rm -rf *.exe *.obj *.pch *.ilk *.pdb
