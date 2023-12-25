const { expect } = require("chai");
const { loadFixture, } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { deployFixture } = require("./deploy_fixture.js");

describe("Gateway Contract", function() {
    describe("Deployment", function() {
        it("Should deploy successfully", async function() {
            const fixture = await loadFixture(deployFixture);
        })
    })
})

