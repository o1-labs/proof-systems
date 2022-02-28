/**
 * Get the existing variable names
 * @returns the set of all different variable names
 */
function getAllVariables() {
    allVariables = document.getElementsByClassName("var")
    s = new Set()
    for (variable of allVariables) {
        classList = variable.classList
        for (className of classList) {
            if (className.startsWith('var_')) {
                s.add(className)
            }
        }
    }
    return s
}


/**
 * Get the variable name of an object
 * @param {Object} obj the object
 * @returns {String} the variable name of the object
 */
function getVariableName(obj) {
    classList = obj.classList
    for (className of classList) {
        if (className.startsWith('var_')) {
            return className
        }
    }
    return ""
}


/**
 * Selects the contents of an element
 * @param {*} el the element to select the contents of
 */
function selectElementContents(el) {
    var range = document.createRange();
    range.selectNodeContents(el.children[0]);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
}

/**
 * Handler for clicking an editable variable.
 * Underlines all objects and selects the content of the current on.
 *
 * @param {*} listObjs list of objects to underline
 * @param {*} obj current object to select
 */
function onClickAction(listObjs, obj) {
    text = obj.innerText.trim()
    for (elem of listObjs) {
        if (!elem.innerHTML.includes("<span")) {
            continue
        }
        if (text.length != 0) {
            elem.setAttribute("style", "border-bottom: 2px solid #aaa;")
        }
    }
    selectElementContents(obj);
}


/**
 * Handler for when you unfocus the editing of a variable.
 * Removes the style of all related objects.
 *
 * @param {*} listObjs list of objects to remove the style
 */
function onBlurAction(listObjs) {
    for (elem of listObjs) {
        // ignore divs without span
        if (!elem.innerHTML.includes('<span')) {
            continue
        }

        // its empty so we dont want to remove the style
        if (!elem.innerHTML.includes("><")) {
            elem.removeAttribute("style")
        }
    }
}


/**
 * Input handler -- underlines and changes the text of all relate objects to the current one.
 * Also updates the local storage.
 *
 * @param {*} elemsWithClassName iterable with the objects of a certain class name
 * @param {*} cur currently edited text
 * @param {*} name variable name
 */
function onInputAction(elemsWithClassName, cur, name) {
    text = cur.innerText.trim()
    toBox = text.length == 0

    for (elem of elemsWithClassName) {

        if (!elem.innerHTML.includes('<span')) {
            continue
        }
        if (toBox) {
            elem.setAttribute("style", "border: 2px solid #aaa;")
        } else {
            elem.setAttribute("style", "border-bottom: 2px solid #aaa;")
        }

        if (elem != cur) {
            var innerSpan = elem.children[0];
            innerSpan.textContent = text;
        }
    }
    // if (cur.innerText.trim().length == 0) {
    //     cur.setAttribute("style", "border: 2px solid #aaa;")
    // }

    updateLocalStorage(name, cur.textContent.trim())
}

/**
 * Update this page's local storage dictionary
 * @param {string} variable_name variable name to be changed
 * @param {string} new_name new value of this variable
 */
function updateLocalStorage(variable_name, new_name) {
    URL_s = window.location.pathname
    data = window.localStorage.getItem(URL_s)
    if (data == null) {
        data = {}
    } else {
        data = JSON.parse(data);
    }
    data[variable_name] = new_name
    window.localStorage.setItem(URL_s, JSON.stringify(data));
}

/**
 * Rename the current page variables according to the local storage
 */
function renameWithLocalStorage() {
    URL_s = window.location.pathname
    data = window.localStorage.getItem(URL_s)
    if (data == null) {
        return
    }

    data = JSON.parse(data);
    for (var key in data) {
        elemsWithClassName = document.body.getElementsByClassName(key)
        for (elem of elemsWithClassName) {
            if (!elem.innerHTML.includes('<span')) {
                continue
            }

            var innerSpan = elem.children[0];
            innerSpan.textContent = data[key];
        }
    }
}

/**
 * Resets the names of the current page to their original value
 */
function resetVariableNames() {
    url = window.location.pathname
    data = window.localStorage.getItem(url)
    if (data == null) {
        return
    }

    data = JSON.parse(data);
    for (var key in data) {
        elemsWithClassName = document.body.getElementsByClassName(key)
        for (elem of elemsWithClassName) {
            if (!elem.innerHTML.includes('<span')) {
                continue
            }
            var innerSpan = elem.children[0];
            innerSpan.textContent = key.split("_")[1];
        }
    }
    window.localStorage.removeItem(url)
}

/**
 * Set variable's elements as editable and configures all handlers, onclick, onblur, input and keydown.
 */
function setEditableAndConfigureHandlers() {
    allVarNames = getAllVariables()

    for (varName of allVarNames) {
        elemsWithClassName = document.body.getElementsByClassName(varName)

        for (o of elemsWithClassName) {
            // not interested in objects with more than 1 child
            if (o.children.length != 1) {
                continue
            }

            // set as editable
            o.setAttribute("contenteditable", "true")

            // set handlers
            o.onclick = (function (elemsWithClassName, obj) {
                return function () {
                    onClickAction(elemsWithClassName, obj);
                }
            })(elemsWithClassName, o);

            o.onblur = (function (elemsWithClassName) {
                return function () {
                    onBlurAction(elemsWithClassName);
                }
            })(elemsWithClassName);

            o.addEventListener('input', (function (elemsWithClassName, obj, name) {
                return function (event) {
                    onInputAction(elemsWithClassName, obj, name)
                }
            })(elemsWithClassName, o, varName))

            o.addEventListener('keydown', (function (o) {
                return function (evt) {
                    // pressed enter
                    if (evt.keyCode === 13 || evt.keyCode === 27) {
                        // console.log("pressed enter or escape. Gonna blur the element", evt.keyCode)
                        o.blur()
                        // unselect text
                        window.getSelection().removeAllRanges();
                        evt.preventDefault()
                    }
                    // press delete or backspace on "empty" label
                    else if (o.innerText.trim().length == 0 && (evt.keyCode === 8 || evt.keyCode === 46)) {
                        // console.log("blocking event", evt.keyCode)
                        evt.preventDefault();
                    }
                }
            })(o))
        }
    }
}

/**
 * Runs after mathjax has finished rendering. It:
 *  - renames variables using local storage
 *  - Sets the variable divs as editable, and configures handlers for click, blur and input
 */
function setupInteractiveVariables() {
    renameWithLocalStorage()

    setEditableAndConfigureHandlers()
}
