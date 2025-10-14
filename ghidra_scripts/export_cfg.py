# -*- coding: utf-8 -*-
"""Ghidra post-script that exports per-function control-flow graphs.

This script is executed inside a Ghidra headless session. It expects an output
path followed by an optional format specifier ("json" or "graphml").
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


def _write_json(program_info, functions, output_path):
    _ensure_parent(output_path)
    with open(output_path, "w") as fd:
        json.dump(
            {"program": program_info, "functions": functions},
            fd,
            indent=2,
            sort_keys=True,
        )
    return True


def _write_graphml(program_info, functions, output_path):
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        printerr("xml.etree.ElementTree is unavailable; cannot export GraphML")
        return False

    graphml = ET.Element(
        "graphml",
        {
            "xmlns": "http://graphml.graphdrawing.org/xmlns",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": (
                "http://graphml.graphdrawing.org/xmlns "
                "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"
            ),
        },
    )

    key_defs = [
        ("d0", "node", "function", "string"),
        ("d1", "node", "start", "string"),
        ("d2", "node", "end", "string"),
        ("d3", "node", "size", "int"),
        ("d4", "graph", "entry_point", "string"),
        ("d5", "edge", "flow_type", "string"),
        ("d6", "graph", "program_name", "string"),
        ("d7", "graph", "language_id", "string"),
        ("d8", "graph", "compiler", "string"),
    ]

    for key_id, target, name, value_type in key_defs:
        key_elem = ET.SubElement(graphml, "key")
        key_elem.set("id", key_id)
        key_elem.set("for", target)
        key_elem.set("attr.name", name)
        key_elem.set("attr.type", value_type)

    for function in functions:
        function_name = function.get("name") or "function"
        entry_point = function.get("entry_point") or "unknown"
        graph_id = "%s@%s" % (function_name, entry_point)
        safe_graph_id = graph_id.replace(" ", "_")
        graph = ET.SubElement(graphml, "graph")
        graph.set("id", safe_graph_id)
        graph.set("edgedefault", "directed")

        entry_data = ET.SubElement(graph, "data")
        entry_data.set("key", "d4")
        entry_data.text = entry_point

        program_name = ET.SubElement(graph, "data")
        program_name.set("key", "d6")
        program_name.text = program_info.get("name") or ""

        language_id = ET.SubElement(graph, "data")
        language_id.set("key", "d7")
        language_id.text = program_info.get("language_id") or ""

        compiler = ET.SubElement(graph, "data")
        compiler.set("key", "d8")
        compiler.text = program_info.get("compiler") or ""

        node_prefix = safe_graph_id
        for block in function.get("blocks", []):
            block_id = block.get("id") or "block"
            node_id = "%s::%s" % (node_prefix, block_id)
            node = ET.SubElement(graph, "node")
            node.set("id", node_id)

            node_func = ET.SubElement(node, "data")
            node_func.set("key", "d0")
            node_func.text = function_name

            node_start = ET.SubElement(node, "data")
            node_start.set("key", "d1")
            node_start.text = block.get("start") or ""

            node_end = ET.SubElement(node, "data")
            node_end.set("key", "d2")
            node_end.text = block.get("end") or ""

            node_size = ET.SubElement(node, "data")
            node_size.set("key", "d3")
            node_size.text = str(block.get("size"))

        edge_index = 0
        for edge in function.get("edges", []):
            edge_elem = ET.SubElement(graph, "edge")
            edge_elem.set("id", "%s::e%d" % (node_prefix, edge_index))
            edge_index += 1

            source = "%s::%s" % (node_prefix, edge.get("source") or "")
            target = "%s::%s" % (node_prefix, edge.get("target") or "")
            edge_elem.set("source", source)
            edge_elem.set("target", target)

            edge_type = ET.SubElement(edge_elem, "data")
            edge_type.set("key", "d5")
            edge_type.text = edge.get("type") or ""

    _ensure_parent(output_path)
    tree = ET.ElementTree(graphml)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return True


def run():
    args = getScriptArgs()
    if not args:
        printerr(
            "Missing output path argument. Usage: export_cfg.py <output> [json|graphml]"
        )
        return

    output_path = os.path.abspath(args[0])
    output_format = "json"
    if len(args) > 1 and args[1]:
        output_format = args[1].strip().lower()

    monitor = getMonitor()
    if monitor is None:
        monitor = ConsoleTaskMonitor()

    program = currentProgram
    function_manager = program.getFunctionManager()
    block_model = SimpleBlockModel(program)

    program_info = {
        "name": program.getName(),
        "language_id": program.getLanguage().getLanguageID().getIdAsString(),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    }
    functions = []

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

        functions.append(
            {
                "name": function.getName(),
                "entry_point": _as_hex(function.getEntryPoint()),
                "blocks": block_list,
                "edges": edges,
            }
        )

    writers = {
        "json": _write_json,
        "graphml": _write_graphml,
    }

    writer = writers.get(output_format)
    if writer is None:
        printerr("Unsupported output format: {}".format(output_format))
        return

    if not writer(program_info, functions, output_path):
        printerr("Failed to write CFG in {} format".format(output_format))
        return


run()
