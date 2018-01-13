#!/bin/sh
SRC=$(dirname $(realpath $0))/src
PLUGINS=${HOME}/.binaryninja/plugins
mkdir -p ${PLUGINS}/bpf
ln -sf ${SRC}/binaryninja/plugin.py ${PLUGINS}/bpf/__init__.py
ln -sf ${SRC}/bpftools ${PLUGINS}/bpf/bpftools
mkdir -p ${HOME}/.binaryninja/types/platform
ln -sf ${SRC}/binaryninja/bpf-vm.c ${HOME}/.binaryninja/types/platform/bpf-vm.c