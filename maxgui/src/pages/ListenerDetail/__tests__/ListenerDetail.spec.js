import Vue from 'vue'
import chai /* , { expect } */ from 'chai'
import mount, { router } from '@tests/unit/setup'
import ListenerDetail from '@/pages/ListenerDetail'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { mockupAllListeners } from '@tests/unit/mockup'
chai.should()
chai.use(sinonChai)

describe('ListenerDetail index', () => {
    let wrapper, axiosStub

    before(async () => {
        axiosStub = sinon.stub(Vue.axios, 'get').returns(
            Promise.resolve({
                data: {},
            })
        )

        const listenerPath = `/dashboard/listeners/${mockupAllListeners[0].id}`
        if (router.history.current.path !== listenerPath) await router.push(listenerPath)
    })

    after(async () => {
        await axiosStub.reset()
    })

    beforeEach(async () => {
        await axiosStub.restore()
        axiosStub = sinon.stub(Vue.axios, 'get').returns(
            Promise.resolve({
                data: {},
            })
        )
        wrapper = mount({
            shallow: false,
            component: ListenerDetail,
            computed: {
                currentListener: () => mockupAllListeners[0],
            },
        })
    })
    afterEach(async () => {
        await axiosStub.restore()
    })

    it(`Should send request to get listener, relationships service state
      and module parameters`, async () => {
        await wrapper.vm.$nextTick(async () => {
            let {
                id,
                attributes: {
                    parameters: { protocol },
                },
                relationships: {
                    services: { data: servicesData },
                },
            } = mockupAllListeners[0]

            await axiosStub.should.have.been.calledWith(`/listeners/${id}`)

            await servicesData.forEach(async service => {
                await axiosStub.should.have.been.calledWith(
                    `/services/${service.id}?fields[services]=state`
                )
            })

            await axiosStub.should.have.been.calledWith(
                `/maxscale/modules/${protocol}?fields[module]=parameters`
            )

            axiosStub.should.have.callCount(3)
        })
    })
})