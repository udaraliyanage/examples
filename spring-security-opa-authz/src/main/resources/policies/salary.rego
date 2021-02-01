package authz

default allow = false

#allow user to access only his salary
allow {
  some username
  input.method == "GET"
  input.path = ["salary", username]
  input.name == username
}

#allow HR person to access any one's salary
allow {
  input.method == "GET"
  input.path = ["salary", _]
  input.authorities[_] == "ROLE_HR"
}