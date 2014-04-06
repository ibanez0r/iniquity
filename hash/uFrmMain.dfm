object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'sha1 hash calculator'
  ClientHeight = 300
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Edit1: TEdit
    Left = 8
    Top = 8
    Width = 529
    Height = 21
    TabOrder = 0
  end
  object Memo1: TMemo
    Left = 8
    Top = 35
    Width = 608
    Height = 257
    TabOrder = 1
  end
  object Button1: TButton
    Left = 543
    Top = 6
    Width = 75
    Height = 25
    Caption = 'hash'
    TabOrder = 2
    OnClick = Button1Click
  end
end
