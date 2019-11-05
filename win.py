import PySimpleGUI as sg

layout = [
    [sg.Text('Username'), sg.InputText(key='username')],
    [sg.Text('Password'), sg.InputText(key='password', password_char="*")],
    [sg.Button('Submit')]
]


win = sg.Window('Authentication', layout=layout)
evt, values = win.Read()
print(evt, values)