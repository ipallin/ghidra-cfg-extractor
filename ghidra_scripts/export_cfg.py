# -*- coding: utf-8 -*-
"""Ghidra post-script that exports a function level control-flow graph.

This script is executed inside a Ghidra headless session. It expects a single
argument that indicates where the resulting JSON should be written.
"""

# This script relies on the Jython runtime that ships with Ghidra.

import json
import os

from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import ConsoleTaskMonitor


def _as_hex(address):
    if address is None:
        return None
    return "0x" + address.toString()


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)


def run():
    args = getScriptArgs()
    if not args:
        printerr("Missing output path argument. Usage: export_cfg.py <output.json>")
        return

    output_path = os.path.abspath(args[0])

    monitor = getMonitor()
    if monitor is None:
        monitor = ConsoleTaskMonitor()

    program = currentProgram
    function_manager = program.getFunctionManager()
    block_model = SimpleBlockModel(program)

    result = {
        "program": {
            "name": program.getName(),
            "language_id": program.getLanguage().getLanguageID().getIdAsString(),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        },
        "functions": [],
    }

    function_iter = function_manager.getFunctions(True)
    while function_iter.hasNext() and not monitor.isCancelled():
        function = function_iter.next()
        monitor.setMessage("Exporting CFG for {}".format(function.getName()))

        body = function.getBody()
        block_iter = block_model.getCodeBlocksContaining(body, monitor)

        blocks = {}
        block_list = []
        edges = []

        while block_iter.hasNext() and not monitor.isCancelled():
            block = block_iter.next()
            start = _as_hex(block.getFirstStartAddress())
            end = _as_hex(block.getMaxAddress())
            size = block.getNumAddresses()

            block_info = {
                "id": start,
                "start": start,
                "end": end,
                "size": int(size),
            }
            block_list.append(block_info)
            blocks[start] = block

        for block_id, block in blocks.items():
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext() and not monitor.isCancelled():
                reference = dest_iter.next()
                dest_block = reference.getDestinationBlock()
                if dest_block is None:
                    continue
                dest_id = _as_hex(dest_block.getFirstStartAddress())
                edges.append(
                    {
                        "source": block_id,
                        "target": dest_id,
                        "type": str(reference.getFlowType()),
                    }
                )

        result["functions"].append(
            {
                "name": function.getName(),
                "entry_point": _as_hex(function.getEntryPoint()),
                "blocks": block_list,
                "edges": edges,
            }
        )

    _ensure_parent(output_path)
    with open(output_path, "w") as fd:
        json.dump(result, fd, indent=2, sort_keys=True)


run()
