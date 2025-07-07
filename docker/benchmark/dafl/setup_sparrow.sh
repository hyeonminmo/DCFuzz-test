#!/bin/bash

# setup Sparrow
cd /
git clone https://github.com/prosyslab/sparrow.git

cd /sparrow
git checkout dafl
export OPAMYES=1

apt-get update
apt-get install -y opam libclang-cpp12-dev libgmp-dev libclang-12-dev llvm-12-dev libmpfr-dev

sed -i '/^opam init/ s/$/ --disable-sandboxing/' build.sh
./build.sh

#echo "***********************************************************************************************"
#exit 0
#opam install cli claml ppx_compare yojson ocamlgraph memtrace lymp clangml conf-libclang.12 batteries apron conf-mpfr linenoise
opam install ppx_compare yojson ocamlgraph memtrace lymp clangml conf-libclang.12 batteries apron conf-mpfr cil linenoise claml

eval $(opam env)
make clean
make

