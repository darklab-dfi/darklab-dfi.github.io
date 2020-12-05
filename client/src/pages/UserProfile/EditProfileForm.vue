<!--Jonathan added:Start-->
<!--cd Desktop/ISOM4400/pwc-fyp/vue-paper-dashboard-master-->
<!--add extension in chrome Moesif Origin & CORS Changer-->
<script>
const { request } = require('express');
var express = require('express');
var router = express.Router();
const fetch = require('node-fetch');
const Papa = require('papaparse');
const shodanClient = require('shodan-client');
const urlscan = require('urlscan-api');
const zoomRequest = require('request-promise-native');
const e = require('express');
global.XMLHttpRequest = require("xhr2");
</script>
<!--Jonathan added:End-->

<template>
  <card class="card" title="Edit Profile">
    <div>
      <form @submit.prevent>
        <div class="row">
          <div class="col-md-5">
            <fg-input type="text"
                      label="Company"
                      :disabled="true"
                      placeholder="Paper dashboard"
                      v-model="user.company">
            </fg-input>
          </div>
          <div class="col-md-3">

            <fg-input type="text"
                      label="Username"
                      placeholder="Username"
                      v-model="user.username">
            </fg-input>
          </div>
          <div class="col-md-4">
            <fg-input type="email"
                      label="Username"
                      placeholder="Email"
                      v-model="user.email">
            </fg-input>
          </div>
        </div>

        <div class="row">
          <div class="col-md-6">
            <fg-input type="text"
                      label="First Name"
                      placeholder="First Name"
                      v-model="user.firstName">
            </fg-input>
          </div>
          <div class="col-md-6">
            <fg-input type="text"
                      label="Last Name"
                      placeholder="Last Name"
                      v-model="user.lastName">
            </fg-input>
          </div>
        </div>

        <div class="row">
          <div class="col-md-12">
            <fg-input type="text"
                      label="Address"
                      placeholder="Home Address"
                      v-model="user.address">
            </fg-input>
          </div>
        </div>

        <div class="row">
          <div class="col-md-4">
            <fg-input type="text"
                      label="City"
                      placeholder="City"
                      v-model="user.city">
            </fg-input>
          </div>
          <div class="col-md-4">
            <fg-input type="text"
                      label="Country"
                      placeholder="Country"
                      v-model="user.country">
            </fg-input>
          </div>
          <div class="col-md-4">
            <fg-input type="number"
                      label="Postal Code"
                      placeholder="ZIP Code"
                      v-model="user.postalCode">
            </fg-input>
          </div>
        </div>

        <div class="row">
          <div class="col-md-12">
            <div class="form-group">
              <label>About Me</label>
              <textarea rows="5" class="form-control border-input"
                        placeholder="Here can be your description"
                        v-model="user.aboutMe">

              </textarea>
            </div>
          </div>
        </div>
        <div class="text-center">
          <p-button type="info"
                    round
                    @click.native.prevent="updateProfile">
            Update Profile
          </p-button>
        </div>
        <div class="clearfix"></div>
        <div class="text-center"><!--Jonathan added:Start-->
          <p-button type="info"
                    round
                    @click.native.prevent="securityTrailFunc">
            Get Security Trail Data
          </p-button>
        </div>
        <div class="clearfix"></div>
        <div class="text-center">
          <p-button type="info"
                    round
                    @click.native.prevent="hunterioFunc">
            Get Hunter io Data
          </p-button>
        </div>
        <div class="clearfix"></div><!--Jonathan added:End-->
      </form>
    </div>
  </card>
</template>
<script>
export default {
  data() {
    return {
      user: {
        company: "Paper Dashboard",
        username: "michael23",
        email: "",
        firstName: "Chet",
        lastName: "Faker",
        address: "Melbourne, Australia",
        city: "Melbourne",
        postalCode: "",
        aboutMe: `We must accept finite disappointment, but hold on to infinite hope.`
      }
    };
  },
  methods: {
    updateProfile() {
      alert("Your data: " + JSON.stringify(this.user));
    },
    //Jonathan added:Start
    async securityTrailFunc() {
      var prefixURL = 'https://cors-anywhere.herokuapp.com/'
      var searchDomains = "pwc.com";
      var url =prefixURL + 'https://api.securitytrails.com/v1/history/' + searchDomains + '/dns/a';
      var headers = {
        "accept": "application/json",
        "apikey": "DQBlP4wW3HFKjAA12KHc6NtiYATfTVZP",
      };
      const request_securityTrail = await fetch(url, { method: 'GET', headers: headers});
      const data = await request_securityTrail.json();
      alert(JSON.stringify(data));
    },
    async hunterioFunc(){
      var prefixURL = 'https://cors-anywhere.herokuapp.com/'
      var searchDomains = "pwc.com";
      var hunterAPIkey ="22850ea6e4f33099e48217886b978b65c82db488";
      var url = prefixURL + 'https://api.hunter.io/v2/domain-search?domain=' + searchDomains + '&api_key=' + hunterAPIkey + '&limit=10';
      var headers = {
        "accept": "application/json",
        "apikey": hunterAPIkey
      };
      const request_hunterio = await fetch(url, { method: 'GET', headers: headers}); //must include await
      const data = await request_hunterio.json(); //must include await so that will wait for data return
      alert(JSON.stringify(data));
    }
    //Jonathan added:End
  }
};
</script>
<style>
</style>
