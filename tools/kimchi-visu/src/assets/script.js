const cs = index.cs;
let public = cs.public;
console.log(public);

// display witness?
if (witness) {
    document.querySelector("#gates thead tr").innerHTML += '<th colspan="15" scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Registers</th > ';

    // pad witness
    const witness_padding = cs.gates.length - witness.inner[0].length;
    if (witness_padding > 0) {
        for (let col = 0; col < 15; col++) {
            for (let i = 0; i < witness_padding; i++) {
                witness.inner[col].push(0);
            }
        }
    }
}

// display gates
let poseidon = false
cs.gates.forEach((g, row) => {
    let coeffs = '';

    const coeffs_padding = 15 - g.coeffs.length;
    if (coeffs_padding > 0) {
        // padd coeffs
        for (let i = 0; i < coeffs_padding; i++) {
            g.coeffs.push(0);
        }
    }
    g.coeffs.forEach((c) => {
        let coeff = toTruncatedHex(c);
        coeffs += `<td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${coeff}</td>`;
    });

    const wiring = parseWiring(row, g.wires);
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

    let witness_cols = '';
    if (witness) {
        witness.inner.forEach((col) => {
            witness_cols += `<td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${toTruncatedHex(col[row])}</td>`;
        });
    }

    const gate = `<tr>
                <td class="px-6 py-4 whitespace-nowrap">${row}</td>
                <td class="px-6 py-4 whitespace-nowrap ${gateColor(g.typ)}">${typ}</td>
                <td class="px-6 py-4 whitespace-nowrap">${wiring}</td>
                ${coeffs}
                ${witness_cols}
            </tr>`;
    document.querySelector("#gates tbody").innerHTML += gate;
});

// detect wiring
function parseWiring(row, wires) {
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
    if (byteArray == 0) {
        return '0';
    }
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function toTruncatedHex(byteArray) {
    let hex = toHexString(byteArray);
    if (hex == "0000000000000000000000000000000000000000000000000000000000000000") {
        return "0";
    } else if (hex == "0100000000000000000000000000000000000000000000000000000000000000") {
        return "1";
    } else if (hex == "0200000000000000000000000000000000000000000000000000000000000000") {
        return "2";
    } else if (hex == "0300000000000000000000000000000000000000000000000000000000000000") {
        return "3";
    } else if (hex == "0400000000000000000000000000000000000000000000000000000000000000") {
        return "4";
    } else if (hex.length > 2) {
        hex = `<span title="${hex}">${hex.slice(0, 4)}..</span>`;
    }
    return hex;
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