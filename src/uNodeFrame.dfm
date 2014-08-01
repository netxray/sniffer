object NodeFrame: TNodeFrame
  Left = 0
  Top = 0
  Width = 730
  Height = 395
  Font.Charset = ANSI_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Courier New'
  Font.Style = []
  ParentFont = False
  TabOrder = 0
  object gbNode: TGroupBox
    Left = 0
    Top = 0
    Width = 730
    Height = 152
    Align = alClient
    Caption = 'Node Traffic List'
    TabOrder = 0
    object lvNodeList: TJvListView
      Left = 2
      Top = 17
      Width = 726
      Height = 133
      Align = alClient
      Columns = <
        item
          Caption = 'No'
        end
        item
          Caption = 'IP'
          Width = 110
        end
        item
          Caption = 'Name'
          Width = 80
        end
        item
          Caption = 'Recv Data[Bytes]'
          Width = 150
        end
        item
          Caption = 'Sent Data[Bytes]'
          Width = 150
        end>
      TabOrder = 0
      ViewStyle = vsReport
    end
  end
  object GroupBox1: TGroupBox
    Left = 0
    Top = 152
    Width = 730
    Height = 243
    Align = alBottom
    Caption = 'Traffic Map'
    TabOrder = 1
    object TrafficPnl: TPanel
      Left = 2
      Top = 17
      Width = 726
      Height = 224
      Align = alClient
      BevelOuter = bvLowered
      TabOrder = 0
    end
  end
end
