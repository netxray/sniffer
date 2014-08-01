object frmSelAdapter: TfrmSelAdapter
  Left = 280
  Top = 293
  ActiveControl = btnCL
  BorderStyle = bsDialog
  Caption = 'Select Network Adapter'
  ClientHeight = 153
  ClientWidth = 347
  Color = clBtnFace
  Font.Charset = ANSI_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = #23435#20307
  Font.Style = []
  KeyPreview = True
  OldCreateOrder = False
  Position = poMainFormCenter
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 12
  object Label1: TLabel
    Left = 10
    Top = 18
    Width = 120
    Height = 12
    Caption = 'Network Adapter List'
  end
  object cbxAdapterList: TComboBox
    Left = 8
    Top = 38
    Width = 329
    Height = 20
    Style = csDropDownList
    TabOrder = 0
  end
  object btnOK: TButton
    Left = 182
    Top = 112
    Width = 75
    Height = 25
    Caption = 'OK'
    TabOrder = 1
    OnClick = btnOKClick
  end
  object btnCL: TButton
    Left = 262
    Top = 112
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 2
    OnClick = btnCLClick
  end
  object cbxPktCapLimit: TCheckBox
    Left = 8
    Top = 65
    Width = 129
    Height = 17
    Caption = 'Packets Threshold'
    TabOrder = 3
    OnClick = cbxPktCapLimitClick
  end
  object udPktCapLimit: TUpDown
    Left = 241
    Top = 63
    Width = 15
    Height = 20
    Enabled = False
    TabOrder = 4
  end
end
