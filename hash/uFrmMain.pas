unit uFrmMain;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, DCPcrypt2, DCPsha1;

type
  TForm1 = class(TForm)
    Edit1: TEdit;
    Memo1: TMemo;
    Button1: TButton;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function hash(astr: ansistring): ansistring;
const
  HASHSIZE_BYTES = 20;
var
  digest: array[0..HASHSIZE_BYTES - 1] of byte;
  i: integer;
begin
  with tdcp_sha1.create(nil) do
  try
    init();
    updatestr(astr);
    final(digest[0]);
    result := '';
    for i := 0 to HASHSIZE_BYTES - 1 do
      result := result + inttohex((digest[i]), 2);
    result := lowercase(result);
  finally
    free();
  end;
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
memo1.Lines.Add(hash(edit1.Text));
end;

end.
