SECTIONS {
    _libebpf_functab : SUBALIGN(16) {
        _start_libebpf_exported_function = .;
        KEEP(*(SORT(_libebpf_functab*)))
        _end_libebpf_exported_function = .;     
    }
}
