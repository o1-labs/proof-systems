const cs = index.cs;
let public = cs.public;
console.log(public);

// display witness?
if (witness) {
    document.querySelector("#gates thead tr").innerHTML += '<th colspan="15" scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"> Registers</th > ';
}

// display gates
let poseidon = false
cs.gates.forEach((g, row) => {
    let coeffs = '';
    g.coeffs.forEach((c) => {
        let coeff = toHexString(c);
        if (coeff.length > 2) {
            coeff = `<span title="${coeff}">${coeff.slice(0, 4)}..</span>`;
        }
        coeffs += `<td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${coeff}</td>`;
    });

    const wiring = parse_wiring(row, g.wires);
    let typ = g.typ;
    if (public > 0) {
        typ += '<br>(public input)';
        public -= 1;
    }

    if (typ == "Poseidon") {
        poseidon = true;
    } else if (poseidon) {
        typ += '<br>(w/ output of poseidon)';
        poseidon = false;
    }

    const gate = `<tr>
                <td class="px-6 py-4 whitespace-nowrap">${row}</td>
                <td class="px-6 py-4 whitespace-nowrap ${gateColor(g.typ)}">${typ}</td>
                <td class="px-6 py-4 whitespace-nowrap">${wiring}</td>
                ${coeffs}
            </tr>`;
    document.querySelector("#gates tbody").innerHTML += gate;
});

// detect wiring
function parse_wiring(row, wires) {
    let wiring = '';
    let permutation = false;
    wires.forEach((w, col) => {
        if (col != w.col || row != w.row) {
            permutation = true;
            wiring += `<li>col ${col} -> (row: ${w.row}, col: ${w.col})</li>`;
        }
    });

    if (permutation) {
        return `<ul>${wiring}</ul>`;
    } else {
        return "/";
    }
}

// bytearrays to hex
function toHexString(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

// colors for gates
function gateColor(gate) {
    if (gate == "Generic") {
        return "bg-blue-300";
    } else if (gate == "Poseidon") {
        return "bg-purple-300";
    } else if (gate == "CompleteAdd") {
        return "bg-green-300";
    } else if (gate == "VarBaseMul") {
        return "bg-yellow-300";
    } else if (gate == "EndoMul") {
        return "bg-red-300";
    } else if (gate == "EndoMulScalar") {
        return "bg-orange-300";
    } else if (gate == "ChaCha0") {
        return "bg-teal-300";
    } else if (gate == "ChaCha1") {
        return "bg-pink-300";
    } else if (gate == "ChaCha2") {
        return "bg-stone-300";
    } else if (gate == "ChaChaFinal") {
        return "bg-slate-300";
    } else { // Zero
        return "bg-gray-300";
    }
}