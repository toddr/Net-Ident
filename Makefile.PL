use ExtUtils::MakeMaker;

# this is a hack to make Ident.pm insert a FileHandle method in either
# perl5.003 or perl5.004
{
    use FileHandle;
    package FileHandle; sub ident_lookup {"FileHandle"};
    package IO::Handle; sub ident_lookup {"IO::Handle"};
    package main;
    open(S, $0);
    $pkg = eval { S->ident_lookup };
    if ( !$pkg ) {
	die("cannot determine a way to add a method to a filehandle\n");
    }
    open(IN, "Ident.pm.in") or die("open Ident.pm.in: $!\n");
    open(OUT, ">Ident.pm") or die("write Ident.pm: $!\n");
    local($/);
    undef $/;
    $_ = <IN>;
    s/\@FILEHANDLE\@/$pkg/g;
    print OUT;
    close(IN);
    close(OUT);
}

# back to your regular scheduled MakeMaker
WriteMakefile(
    'NAME'	=> 'Net::Ident',
    'VERSION_FROM' => 'Ident.pm', # finds $VERSION
    'clean' => {FILES => "Ident.pm"}, # cleans Ident.pm
);
